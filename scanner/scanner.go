// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package scanner holds code for iterating through the contents of a CT log.
package scanner

import (
	"container/list"
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"database/sql"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/x509"
)

// ScannerOptions holds configuration options for the Scanner
type ScannerOptions struct { // nolint:golint
	// Custom matcher for x509 Certificates, functor will be called for each
	// Certificate found during scanning.
	Matcher Matcher

	// Match precerts only (Matcher still applies to precerts)
	PrecertOnly bool

	// Number of entries to request in one batch from the Log
	BatchSize int

	// Number of concurrent matchers to run
	NumWorkers int

	// Number of concurrent fethers to run
	ParallelFetch int

	// Log entry index to start fetching & matching at
	StartIndex int64

	// Don't print any status messages to stdout
	Quiet bool
}

// DefaultScannerOptions creates a new ScannerOptions struct with sensible defaults.
func DefaultScannerOptions() *ScannerOptions {
	return &ScannerOptions{
		Matcher:       &MatchAll{},
		PrecertOnly:   false,
		BatchSize:     1000,
		NumWorkers:    1,
		ParallelFetch: 1,
		StartIndex:    0,
		Quiet:         false,
	}
}

// Scanner is a tool to scan all the entries in a CT Log.
type Scanner struct {
	// Client used to talk to the CT log instance
	logClient *client.LogClient

	// Configuration options for this Scanner instance
	opts ScannerOptions

	// Counter of the number of certificates scanned
	certsProcessed int64

	// Counter of the number of precertificates encountered during the scan.
	precertsSeen int64

	unparsableEntries         int64
	entriesWithNonFatalErrors int64

	Log func(msg string)
}

// entryInfo represents information about a log entry
type entryInfo struct {
	// The index of the entry containing the LeafInput in the log
	index int64
	// The log entry returned by the log server
	entry ct.LeafEntry
}

// fetchRange represents a range of certs to fetch from a CT log
type fetchRange struct {
	start int64 // inclusive
	end   int64 // inclusive
}

// Takes the error returned by either x509.ParseCertificate() or
// x509.ParseTBSCertificate() and determines if it's non-fatal or otherwise.
// In the case of non-fatal errors, the error will be logged,
// entriesWithNonFatalErrors will be incremented, and the return value will be
// false.
// Fatal errors will cause the function to return true.
// When err is nil, this method does nothing.
func (s *Scanner) isCertErrorFatal(err error, logEntry *ct.LogEntry, index int64) bool {
	if err == nil {
		// No error to handle
		return false
	} else if _, ok := err.(x509.NonFatalErrors); ok {

		db, err_sql := sql.Open("postgres", "user=postgres password=postgres dbname=ct2")
		if err_sql != nil {
			//log.Fatal(err_sql)
			s.Log(fmt.Sprintf("sql error in error handling"))
		}
		var data []byte
		if logEntry.Leaf.TimestampedEntry.EntryType == 1 {
			data = logEntry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate
		} else {
			data = logEntry.Leaf.TimestampedEntry.X509Entry.Data
		}

		_, err_sql = db.Exec("INSERT INTO unparsable VALUES ($1, $2);", data, string(err.Error()))
		if err_sql != nil {
			s.Log(fmt.Sprintf("sql error in error handling"))
			//log.Fatal(err_sql)
		}
		db.Close()

		atomic.AddInt64(&s.entriesWithNonFatalErrors, 1)
		// We'll make a note, but continue.
		s.Log(fmt.Sprintf("Non-fatal error in %+v at index %d: %s", logEntry.Leaf.TimestampedEntry.EntryType, index, err.Error()))
		return false
	}
	return true
}

// Processes the given entry in the specified log.
func (s *Scanner) processEntry(index int64, entry ct.LeafEntry, foundCert func(*ct.LogEntry), foundPrecert func(*ct.LogEntry)) error {
	atomic.AddInt64(&s.certsProcessed, 1)

	logEntry, err := ct.LogEntryFromLeaf(index, &entry)
	if s.isCertErrorFatal(err, logEntry, index) {
		return fmt.Errorf("failed to parse [pre-]certificate in MerkleTreeLeaf: %v", err)
	}

	switch {
	case logEntry.X509Cert != nil:
		if s.opts.PrecertOnly {
			// Only interested in precerts and this is an X.509 cert, early-out.
			return nil
		}
		if s.opts.Matcher.CertificateMatches(logEntry.X509Cert) {
			foundCert(logEntry)
		}
	case logEntry.Precert != nil:
		if s.opts.Matcher.PrecertificateMatches(logEntry.Precert) {
			foundPrecert(logEntry)
		}
		atomic.AddInt64(&s.precertsSeen, 1)
	default:
		return fmt.Errorf("saw unknown entry type: %v", logEntry.Leaf.TimestampedEntry.EntryType)
	}
	return nil
}

// Worker function to match certs.
// Accepts MatcherJobs over the entries channel, and processes them.
// Returns true over the done channel when the entries channel is closed.
func (s *Scanner) matcherJob(entries <-chan entryInfo, foundCert func(*ct.LogEntry), foundPrecert func(*ct.LogEntry)) {
	for e := range entries {
		if err := s.processEntry(e.index, e.entry, foundCert, foundPrecert); err != nil {
			atomic.AddInt64(&s.unparsableEntries, 1)
			s.Log(fmt.Sprintf("Failed to parse entry at index %d: %s", e.index, err.Error()))
		}
	}
}

// Worker function for fetcher jobs.
// Accepts cert ranges to fetch over the ranges channel, and if the fetch is
// successful sends the individual LeafInputs out (as MatcherJobs) into the
// entries channel for the matchers to chew on.
// Will retry failed attempts to retrieve ranges indefinitely.
// Sends true over the done channel when the ranges channel is closed.
func (s *Scanner) fetcherJob(ctx context.Context, ranges <-chan fetchRange, entries chan<- entryInfo) {
	for r := range ranges {
		success := false
		// TODO(alcutter): give up after a while:
		for !success {
			resp, err := s.logClient.GetRawEntries(ctx, r.start, r.end)
			if err != nil {
				s.Log(fmt.Sprintf("Problem fetching from log: %s", err.Error()))
				continue
			}
			for _, leafEntry := range resp.Entries {
				entries <- entryInfo{r.start, leafEntry}
				r.start++
			}
			if r.start > r.end {
				// Only complete if we actually got all the leaves we were
				// expecting -- Logs MAY return fewer than the number of
				// leaves requested.
				success = true
			}
		}
	}
}

func min(a int64, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func max(a int64, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// Pretty prints the passed in number of seconds into a more human readable
// string.
func humanTime(seconds int) string {
	nanos := time.Duration(seconds) * time.Second
	hours := int(nanos / (time.Hour))
	nanos %= time.Hour
	minutes := int(nanos / time.Minute)
	nanos %= time.Minute
	seconds = int(nanos / time.Second)
	s := ""
	if hours > 0 {
		s += fmt.Sprintf("%d hours ", hours)
	}
	if minutes > 0 {
		s += fmt.Sprintf("%d minutes ", minutes)
	}
	if seconds > 0 {
		s += fmt.Sprintf("%d seconds ", seconds)
	}
	return s
}

func minimum(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Scan performs a scan against the Log.
// For each x509 certificate found, foundCert will be called with the
// index of the entry and certificate itself as arguments.  For each precert
// found, foundPrecert will be called with the index of the entry and the raw
// precert string as the arguments.
//
// This method blocks until the scan is complete.
func (s *Scanner) Scan(ctx context.Context, foundCert func(*ct.LogEntry), foundPrecert func(*ct.LogEntry)) (int64, error) {
	s.Log("Starting up...\n")
	s.certsProcessed = 0
	s.precertsSeen = 0
	s.unparsableEntries = 0
	s.entriesWithNonFatalErrors = 0

	latestSthTmp, err := s.logClient.GetSTH(ctx)
	latestSth := minimum(100000, int(latestSthTmp.TreeSize))
	s.Log(fmt.Sprintf("Real Tree Size: %d, Will use Tree Size: %d", latestSthTmp.TreeSize, latestSth))
	if err != nil {
		return int64(latestSth), err
	}
	s.Log(fmt.Sprintf("Got STH with %d certs", latestSth))

	ticker := time.NewTicker(time.Second)
	startTime := time.Now()
	fetches := make(chan fetchRange, 1000)
	jobs := make(chan entryInfo, 100000)
	go func() {
		for range ticker.C {
			certsProcessed := atomic.LoadInt64(&s.certsProcessed)
			throughput := float64(certsProcessed) / time.Since(startTime).Seconds()
			remainingCerts := int64(latestSth) - int64(s.opts.StartIndex) - certsProcessed
			remainingSeconds := int(float64(remainingCerts) / throughput)
			remainingString := humanTime(remainingSeconds)
			s.Log(fmt.Sprintf("Processed: %d certs (to index %d). Throughput: %3.2f ETA: %s\n", certsProcessed,
				s.opts.StartIndex+int64(certsProcessed), throughput, remainingString))
		}
	}()

	var ranges list.List
	// TODO in next line: replace 0 with s.opts.StartIndex
	for start := int64(s.opts.StartIndex); start < int64(latestSth); {
		// TODO end := min(start+int64(s.opts.BatchSize), int64(latestSth.TreeSize)) - 1
		end := min(start+int64(s.opts.BatchSize), int64(latestSth)) - 1
		ranges.PushBack(fetchRange{start, end})
		start = end + 1
	}
	var fetcherWG sync.WaitGroup
	var matcherWG sync.WaitGroup
	// Start matcher workers
	for w := 0; w < s.opts.NumWorkers; w++ {
		matcherWG.Add(1)
		go func(w int) {
			defer matcherWG.Done()
			s.matcherJob(jobs, foundCert, foundPrecert)
			s.Log(fmt.Sprintf("Matcher %d finished", w))
		}(w)
	}
	// Start fetcher workers
	for w := 0; w < s.opts.ParallelFetch; w++ {
		fetcherWG.Add(1)
		go func(w int) {
			defer fetcherWG.Done()
			s.fetcherJob(ctx, fetches, jobs)
			s.Log(fmt.Sprintf("Fetcher %d finished", w))
		}(w)
	}
	for r := ranges.Front(); r != nil; r = r.Next() {
		fetches <- r.Value.(fetchRange)
	}
	close(fetches)
	fetcherWG.Wait()
	close(jobs)
	matcherWG.Wait()

	s.Log(fmt.Sprintf("Completed %d certs in %s", atomic.LoadInt64(&s.certsProcessed), humanTime(int(time.Since(startTime).Seconds()))))
	s.Log(fmt.Sprintf("Saw %d precerts", atomic.LoadInt64(&s.precertsSeen)))
	s.Log(fmt.Sprintf("%d unparsable entries, %d non-fatal errors", atomic.LoadInt64(&s.unparsableEntries), atomic.LoadInt64(&s.entriesWithNonFatalErrors)))
	return int64(latestSth), nil
}

// NewScanner creates a new Scanner instance using client to talk to the log,
// taking configuration options from opts.
func NewScanner(client *client.LogClient, opts ScannerOptions) *Scanner {
	var scanner Scanner
	scanner.logClient = client
	// Set a default match-everything regex if none was provided:
	if opts.Matcher == nil {
		opts.Matcher = &MatchAll{}
	}
	if opts.Quiet {
		scanner.Log = func(msg string) {}
	} else {
		scanner.Log = func(msg string) { log.Print(msg) }
	}
	scanner.opts = opts
	return &scanner
}
