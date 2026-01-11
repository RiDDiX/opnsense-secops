#!/bin/bash
# Compare two security scans to see what changed

if [ $# -ne 2 ]; then
    echo "Usage: $0 <old_report.json> <new_report.json>"
    exit 1
fi

OLD_REPORT=$1
NEW_REPORT=$2

if [ ! -f "$OLD_REPORT" ] || [ ! -f "$NEW_REPORT" ]; then
    echo "Error: One or both report files not found"
    exit 1
fi

echo "=========================================="
echo "Security Scan Comparison"
echo "=========================================="
echo "Old: $OLD_REPORT"
echo "New: $NEW_REPORT"
echo ""

# Extract summaries
OLD_CRITICAL=$(grep -o '"critical": [0-9]*' "$OLD_REPORT" | head -n1 | grep -o '[0-9]*')
NEW_CRITICAL=$(grep -o '"critical": [0-9]*' "$NEW_REPORT" | head -n1 | grep -o '[0-9]*')

OLD_HIGH=$(grep -o '"high": [0-9]*' "$OLD_REPORT" | head -n1 | grep -o '[0-9]*')
NEW_HIGH=$(grep -o '"high": [0-9]*' "$NEW_REPORT" | head -n1 | grep -o '[0-9]*')

OLD_TOTAL=$(grep -o '"total_findings": [0-9]*' "$OLD_REPORT" | head -n1 | grep -o '[0-9]*')
NEW_TOTAL=$(grep -o '"total_findings": [0-9]*' "$NEW_REPORT" | head -n1 | grep -o '[0-9]*')

# Calculate differences
CRITICAL_DIFF=$((NEW_CRITICAL - OLD_CRITICAL))
HIGH_DIFF=$((NEW_HIGH - OLD_HIGH))
TOTAL_DIFF=$((NEW_TOTAL - OLD_TOTAL))

# Display comparison
echo "Findings Comparison:"
echo "-------------------"
printf "%-15s %10s %10s %10s\n" "Severity" "Old" "New" "Change"
printf "%-15s %10s %10s %10s\n" "--------" "---" "---" "------"
printf "%-15s %10d %10d %+10d\n" "Critical" "$OLD_CRITICAL" "$NEW_CRITICAL" "$CRITICAL_DIFF"
printf "%-15s %10d %10d %+10d\n" "High" "$OLD_HIGH" "$NEW_HIGH" "$HIGH_DIFF"
printf "%-15s %10d %10d %+10d\n" "Total" "$OLD_TOTAL" "$NEW_TOTAL" "$TOTAL_DIFF"
echo ""

# Interpretation
if [ $CRITICAL_DIFF -gt 0 ]; then
    echo "⚠️  WARNING: Critical findings increased by $CRITICAL_DIFF!"
elif [ $CRITICAL_DIFF -lt 0 ]; then
    echo "✅ GOOD: Critical findings decreased by ${CRITICAL_DIFF#-}"
else
    echo "ℹ️  No change in critical findings"
fi

if [ $TOTAL_DIFF -gt 0 ]; then
    echo "⚠️  Total findings increased by $TOTAL_DIFF"
elif [ $TOTAL_DIFF -lt 0 ]; then
    echo "✅ Total findings decreased by ${TOTAL_DIFF#-}"
else
    echo "ℹ️  No change in total findings"
fi

echo ""
echo "=========================================="
