## 🚀 Credit Optimization Features

This scanner includes advanced credit-saving features to maximize efficiency with limited Shodan API credits.

---

## ✨ New Files Created

### 1. `src/optimized_scanner.py`
**Credit-efficient scanner implementation**

Features:
- ✅ Optimized queries (5 instead of 9)
- ✅ Smart node caching
- ✅ Selective enrichment
- ✅ Adaptive pagination
- ✅ Credit usage tracking

### 2. `scripts/optimized_scan.sh`
**Automated optimized scanning**

Modes:
- `--quick`: 5 query + 50 scan credits
- `--medium`: 5 query + 75 scan credits
- `--full`: 5 query + 100 scan credits

### 3. `scripts/credit_tracker.py`
**Credit usage monitoring**

Features:
- Usage history tracking
- Monthly projections
- Recommendations
- Detailed reports

---

## 📊 Credit Savings Comparison

### Without Optimization:
```
9 queries × 100 results = 900 nodes
Enrichment: ~900 nodes × 1 credit = 900 scan credits
Total: 9 query + 900 scan credits
```

### With Optimization:
```
5 queries × 100 results = 500 nodes (cached: 350)
Enrichment: ~100 critical nodes × 1 credit = 100 scan credits
Total: 5 query + 100 scan credits
```

### Savings:
- **Query credits:** 44% savings (9 → 5)
- **Scan credits:** 89% savings (900 → 100)
- **Overall:** ~85% reduction in credit usage

---

## 🎯 Quick Start

### Option 1: Use Optimized Scan Script (Recommended)

```bash
# Quick scan (most efficient)
./scripts/optimized_scan.sh --quick

# Check credits and usage
./scripts/optimized_scan.sh --check-credits

# Full scan with all features
./scripts/optimized_scan.sh --full
```

### Option 2: Use Python Directly

```bash
# Activate virtualenv
source venv/bin/activate

# Quick scan
python src/optimized_scanner.py --quick

# Full scan without cache
python src/optimized_scanner.py --no-cache --max-enrich 100

# Check credits
python src/optimized_scanner.py --check-credits
```

---

## 📈 Credit Usage Tracking

### View Usage Report

```bash
python scripts/credit_tracker.py --report
```

Output example:
```
================================================================================
SHODAN CREDIT USAGE REPORT
================================================================================

Month: 2026-01
Total scans: 4

QUERY CREDITS:
  Used:              20
  Projected (EOM):   60
  Limit:             100
  Remaining:         80
  Projected remain:  40

SCAN CREDITS:
  Used:              200
  Projected (EOM):   600
  Limit:             100
  Remaining:         -100
  Projected remain:  -500

RECOMMENDATIONS:
⚠️  WARNING: Projected to exceed scan credit limit by 500 credits
   → Reduce enrichment scope
   → Only enrich CRITICAL nodes
```

### Manual Logging

```bash
# Log a manual scan
python scripts/credit_tracker.py --log \
    --query-credits 5 \
    --scan-credits 50 \
    --type quick \
    --notes "Weekly monitoring scan"
```

---

## 🔧 Configuration

### Modify Optimization Settings

Edit `src/optimized_scanner.py`:

```python
class OptimizedConfig(Config):
    # Reduce to 3 queries for maximum savings
    QUERIES_OPTIMIZED = [
        'product:Bitcoin port:8333',
        'port:8332',  # RPC only
        '"Bitcoin Knots"',
    ]
    
    # Adjust cache age (days)
    CACHE_MAX_AGE_DAYS = 14  # Cache for 2 weeks
    
    # Limit enrichment
    MAX_ENRICHMENTS = 50  # Only enrich 50 nodes max
```

---

## 📋 Optimization Strategies Explained

### 1. Query Optimization
**Before:** 9 separate queries
```python
'product:Bitcoin'
'port:8333'
'"Satoshi" port:8333'  # Duplicate!
'port:8332'
'"Bitcoin Core"'       # Duplicate!
'bitcoin'              # Duplicate!
'"Bitcoin Knots"'
'"btcd"'
'"bcoin"'
```

**After:** 5 combined queries
```python
'product:Bitcoin port:8333'  # Combines 5 queries
'port:8332'                  # Keep separate (critical)
'"Bitcoin Knots"'
'"btcd"'
'"bcoin"'
```

**Savings:** 44% (4 credits per scan)

---

### 2. Smart Caching
**How it works:**
1. Scan creates cache of all discovered nodes
2. Next scan checks cache first
3. Only fetch new/changed nodes
4. Cache expires after 7 days (configurable)

**Example:**
- First scan: 500 nodes (5 query credits)
- Second scan (1 week later): 100 new nodes (5 query credits)
- Savings: 80% of enrichment credits

**Cache location:** `cache/nodes_cache.json`

---

### 3. Selective Enrichment
**Only enrich nodes with:**
- RPC exposed (port 8332) - CRITICAL
- Known vulnerable versions - HIGH
- Multiple risk factors - HIGH

**Skip enrichment for:**
- Secure configurations - LOW
- Recent versions - LOW/MEDIUM

**Result:**
- Typical: 10-15% of nodes need enrichment
- Savings: 85-90% of scan credits

---

### 4. Adaptive Pagination
**Smart result limits:**
- Critical queries (RPC): 1000 results
- Normal queries: 100 results

**Why:**
- RPC nodes are rare but critical
- Most queries find plenty in 100 results
- Reduces data transfer and processing

---

## 📊 Monthly Planning

### Membership Plan (100 credits/month)

**Recommended Schedule:**

| Week | Scan Type | Query Credits | Scan Credits | Total |
|------|-----------|---------------|--------------|-------|
| 1 | Quick | 5 | 50 | 55 |
| 2 | Skip | 0 | 0 | 0 |
| 3 | Quick | 5 | 50 | 55 |
| 4 | Medium | 5 | 75 | 80 |
| **Total** | | **15** | **175** | **190** |

⚠️ **Over budget!** Need to adjust:

**Option A:** Reduce enrichment
- Week 1: Quick (5q + 30s)
- Week 3: Quick (5q + 30s)
- Week 4: Medium (5q + 40s)
- **Total:** 15q + 100s = **115 credits** ✅

**Option B:** Use cache more
- Week 1: Full scan (5q + 50s)
- Week 2-4: Use cache (0q + 0s)
- **Total:** 5q + 50s = **55 credits** ✅

---

## 🎓 Best Practices

### 1. Start Conservative
```bash
# First month: measure actual usage
./scripts/optimized_scan.sh --quick
# Wait 1 week
./scripts/optimized_scan.sh --quick
# Wait 1 week
./scripts/optimized_scan.sh --medium
# Check usage
./scripts/optimized_scan.sh --check-credits
```

### 2. Monitor Trends
```bash
# Weekly check
python scripts/credit_tracker.py --report
```

### 3. Adjust Based on Data
- If under 50% usage → Increase frequency
- If over 80% usage → Reduce enrichment
- If over 100% → Enable more caching

### 4. Leverage Cache
```bash
# First scan of month: full
./scripts/optimized_scan.sh --full

# Rest of month: use cache
./scripts/optimized_scan.sh --quick  # Cache will save credits
```

---

## ⚙️ Advanced Usage

### Custom Query Sets

Create your own optimized queries:

```python
# In optimized_scanner.py
QUERIES_CUSTOM = [
    'port:8332',  # Only RPC (most critical)
]

# Or focus on specific versions
QUERIES_VULNERABLE = [
    'product:Bitcoin version:0.18',  # Known vulnerable
    'product:Bitcoin version:0.19',
    'port:8332',
]
```

### Enrichment Rules

Customize what gets enriched:

```python
def should_enrich(node_data):
    """Custom enrichment logic"""
    
    # Only RPC
    if node_data['port'] == 8332:
        return True
    
    # Only very old versions
    version = node_data.get('version', '')
    if '0.13' in version or '0.14' in version:
        return True
    
    return False
```

### Cache Management

```python
from src.optimized_scanner import CachedNodeManager

# Clear cache
cache = CachedNodeManager()
cache.cache = {}
cache.save_cache()

# View cache stats
stats = cache.get_stats()
print(f"Cached: {stats['total_cached']} nodes")
```

---

## 🐛 Troubleshooting

### High Credit Usage?

**Check:**
```bash
python scripts/credit_tracker.py --report
```

**Common issues:**
1. Cache not being used → Check `cache/` directory exists
2. Too many enrichments → Reduce `--max-enrich`
3. Frequent full scans → Use `--quick` more often

### Cache Not Working?

**Verify:**
```bash
# Check cache file exists
ls -la cache/nodes_cache.json

# View cache size
wc -l cache/nodes_cache.json

# Clear and rebuild
rm cache/nodes_cache.json
./scripts/optimized_scan.sh --quick
```

### Scan Too Slow?

**Speed up:**
```bash
# Reduce results
python src/optimized_scanner.py --max-enrich 25

# Skip enrichment
python src/optimized_scanner.py --no-enrich
```

---

## 📞 Support

**Questions about optimization?**
- Check: `docs/SHODAN_CREDITS_OPTIMIZATION.md`
- Review: Credit usage with `--check-credits`
- Contact: security@hacknodes.com

---

**Version:** 1.0  
**Last Updated:** January 4, 2026  
**Author:** HackNodes Lab
