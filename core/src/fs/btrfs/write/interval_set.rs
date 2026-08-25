//! Disjoint sorted interval set for double-allocation tracking.
//!
//! Maintains a collection of non-overlapping, half-open ranges `[start, end)`
//! sorted by start address. Detects overlaps in $O(\log K)$ time.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntervalSet {
    intervals: Vec<(u64, u64)>, // sorted strictly by start: interval[i].1 < interval[i+1].0
}

impl IntervalSet {
    /// Create an empty interval set.
    pub fn new() -> Self {
        Self {
            intervals: Vec::new(),
        }
    }

    /// Check if `[start, start + length)` overlaps with any existing interval in the set.
    pub fn overlaps(&self, start: u64, length: u64) -> bool {
        if length == 0 {
            return false;
        }
        let end = match start.checked_add(length) {
            Some(e) => e,
            None => return true,
        };

        // Binary search for insertion point
        let idx = self.intervals.partition_point(|&(s, _)| s < end);
        if idx > 0 {
            let (_, prev_end) = self.intervals[idx - 1];
            if prev_end > start {
                return true;
            }
        }
        false
    }

    /// Insert `[start, start + length)` into the set.
    /// Returns `true` if inserted successfully without overlap,
    /// or `false` if an overlap was detected (double allocation).
    pub fn insert(&mut self, start: u64, length: u64) -> bool {
        if length == 0 {
            return true;
        }
        let end = match start.checked_add(length) {
            Some(e) => e,
            None => return false,
        };

        let idx = self.intervals.partition_point(|&(s, _)| s < end);
        if idx > 0 {
            let (_, prev_end) = self.intervals[idx - 1];
            if prev_end > start {
                return false; // Overlap detected!
            }
        }

        // Insert and merge with adjacent intervals if touching
        let mut new_start = start;
        let mut new_end = end;
        let mut remove_start = idx;
        let mut remove_end = idx;

        // Check merge with previous interval if touching
        if idx > 0 && self.intervals[idx - 1].1 == start {
            new_start = self.intervals[idx - 1].0;
            remove_start = idx - 1;
        }

        // Check merge with next interval if touching
        if idx < self.intervals.len() && self.intervals[idx].0 == end {
            new_end = self.intervals[idx].1;
            remove_end = idx + 1;
        }

        self.intervals
            .splice(remove_start..remove_end, std::iter::once((new_start, new_end)));
        true
    }

    /// Remove an interval `[start, start + length)` from the set (e.g. during rollback).
    pub fn remove(&mut self, start: u64, length: u64) {
        if length == 0 {
            return;
        }
        let end = match start.checked_add(length) {
            Some(e) => e,
            None => return,
        };

        let mut new_intervals = Vec::new();
        for (s, e) in self.intervals.drain(..) {
            if e <= start || s >= end {
                new_intervals.push((s, e));
            } else {
                if s < start {
                    new_intervals.push((s, start));
                }
                if e > end {
                    new_intervals.push((end, e));
                }
            }
        }
        self.intervals = new_intervals;
    }

    /// Number of disjoint intervals in the set.
    pub fn len(&self) -> usize {
        self.intervals.len()
    }

    /// Whether the interval set is empty.
    pub fn is_empty(&self) -> bool {
        self.intervals.is_empty()
    }

    /// Clear all intervals in the set.
    pub fn clear(&mut self) {
        self.intervals.clear();
    }

    /// Borrow the sorted disjoint intervals as `[(start, end)]`.
    pub fn intervals(&self) -> &[(u64, u64)] {
        &self.intervals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interval_set_insert_and_merge() {
        let mut set = IntervalSet::new();
        assert!(set.insert(100, 50)); // [100, 150)
        assert_eq!(set.intervals(), &[(100, 150)]);

        assert!(set.insert(200, 50)); // [200, 250)
        assert_eq!(set.intervals(), &[(100, 150), (200, 250)]);

        // Merge adjacent touching interval [150, 200)
        assert!(set.insert(150, 50));
        assert_eq!(set.intervals(), &[(100, 250)]);
    }

    #[test]
    fn test_interval_set_detects_overlap() {
        let mut set = IntervalSet::new();
        assert!(set.insert(1000, 500)); // [1000, 1500)

        // Exact match overlap
        assert!(!set.insert(1000, 500));

        // Partial overlap left
        assert!(!set.insert(800, 300)); // [800, 1100) overlaps with [1000, 1500)

        // Partial overlap right
        assert!(!set.insert(1400, 200)); // [1400, 1600) overlaps with [1000, 1500)

        // Enclosed overlap
        assert!(!set.insert(1100, 100)); // [1100, 1200)

        // Enclosing overlap
        assert!(!set.insert(500, 2000)); // [500, 2500)

        // Disjoint does not overlap
        assert!(set.insert(500, 400)); // [500, 900)
        assert!(set.insert(1600, 400)); // [1600, 2000)
        assert_eq!(set.intervals(), &[(500, 900), (1000, 1500), (1600, 2000)]);
    }

    #[test]
    fn test_interval_set_remove() {
        let mut set = IntervalSet::new();
        set.insert(100, 200); // [100, 300)
        set.remove(150, 50); // remove [150, 200)
        assert_eq!(set.intervals(), &[(100, 150), (200, 300)]);
    }
}
