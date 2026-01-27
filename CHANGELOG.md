# Changelog

All notable changes to Ariadne will be documented in this file.

## [Unreleased]

### Added

#### Session Management
- Thread-safe `SessionStore` class with automatic TTL-based cleanup
- Background daemon thread for expired session cleanup (5-minute interval)
- Configurable session TTL via `WebConfig.session_ttl_hours`

#### LLM Client Improvements
- Retry logic with exponential backoff for transient failures
- Custom exceptions: `LLMError`, `LLMTimeoutError`, `LLMRateLimitError`
- Configurable timeout, max retries, and retry delay in `LLMConfig`
- Rate limit detection with extended backoff (4x multiplier)

#### Path Finding Scalability
- Timeout protection for path finding operations using `ThreadPoolExecutor`
- Attack subgraph caching with thread-safe invalidation
- `max_paths` limit parameter to prevent runaway path enumeration
- `PathFindingTimeout` exception for timeout handling
- New config options: `path_timeout_seconds`, `max_paths_per_query`

#### Graph Visualization
- Server-side pagination for `/visualization` endpoint
- Filter by node type parameter
- Pagination metadata in API responses
- JavaScript `loadMore()` method for incremental graph loading

#### Parser Registry
- Logging for parser discovery failures (replaces silent exceptions)
- Cloud parser registration (AWS Scout, Azure Enum)

#### MITRE ATT&CK Techniques
- External YAML configuration support for technique definitions
- `TechniqueMapper` accepts optional config file path
- Fallback to built-in defaults when no config provided
- New `mitre_techniques_path` config option

### Changed

#### Memory Optimization
- Removed redundant `model_dump()` storage in graph nodes
- Added `get_entity_data()` and `get_entity()` accessor methods
- Entity data accessed on-demand instead of duplicated per node

### Fixed

- Silent exception handling in parser registry now logs warnings
- Unused imports removed from multiple modules

## Configuration Changes

### New LLMConfig Options
```yaml
llm:
  timeout: 60          # Request timeout in seconds
  max_retries: 3       # Maximum retry attempts
  retry_delay: 1.0     # Base delay for exponential backoff
```

### New ScoringConfig Options
```yaml
scoring:
  path_timeout_seconds: 30.0   # Timeout for path finding
  max_paths_per_query: 100     # Maximum paths to return
```

### New AriadneConfig Options
```yaml
mitre_techniques_path: null    # Path to custom MITRE techniques YAML
```

## API Changes

### GET /api/graph/{session_id}/visualization

New query parameters:
- `offset` (int, default: 0) - Number of nodes to skip
- `limit` (int, default: 500) - Maximum nodes to return
- `node_type` (string, optional) - Filter by node type

Response now includes pagination metadata:
```json
{
  "elements": { "nodes": [...], "edges": [...] },
  "pagination": {
    "offset": 0,
    "limit": 500,
    "total_nodes": 1234,
    "total_edges": 5678,
    "returned_nodes": 500,
    "returned_edges": 234,
    "has_more": true
  }
}
```

## JavaScript API Changes

### AriadneGraph.loadData(sessionId, options)
Now accepts options object:
```javascript
graph.loadData(sessionId, {
  offset: 0,
  limit: 500,
  nodeType: 'host'
});
```

### New Methods
- `loadMore(sessionId, options)` - Load additional nodes incrementally
- `getPagination()` - Get current pagination state
