/**
 * Ariadne Graph Visualization
 * Uses Cytoscape.js for interactive graph rendering
 */

class AriadneGraph {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.cy = null;
        this.pagination = null;
    }

    async init() {
        if (typeof cytoscape === 'undefined') {
            console.warn('Cytoscape.js not loaded');
            return;
        }

        this.cy = cytoscape({
            container: this.container,
            style: this.getStylesheet(),
            layout: { name: 'cose' },
            minZoom: 0.1,
            maxZoom: 3,
        });
    }

    getStylesheet() {
        return [
            {
                selector: 'node',
                style: {
                    'background-color': '#58a6ff',
                    'label': 'data(label)',
                    'color': '#c9d1d9',
                    'font-size': '10px',
                    'text-valign': 'bottom',
                    'text-margin-y': '5px',
                },
            },
            {
                selector: 'node[type="host"]',
                style: {
                    'background-color': '#3fb950',
                    'shape': 'rectangle',
                },
            },
            {
                selector: 'node[type="service"]',
                style: {
                    'background-color': '#58a6ff',
                    'shape': 'ellipse',
                },
            },
            {
                selector: 'node[type="user"]',
                style: {
                    'background-color': '#d29922',
                    'shape': 'diamond',
                },
            },
            {
                selector: 'node[type="vulnerability"]',
                style: {
                    'background-color': '#f85149',
                    'shape': 'triangle',
                },
            },
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': '#30363d',
                    'target-arrow-color': '#30363d',
                    'target-arrow-shape': 'triangle',
                    'curve-style': 'bezier',
                },
            },
            {
                selector: 'edge[type="can_exploit"]',
                style: {
                    'line-color': '#f85149',
                    'target-arrow-color': '#f85149',
                },
            },
            {
                selector: ':selected',
                style: {
                    'border-width': 3,
                    'border-color': '#ffffff',
                },
            },
        ];
    }

    /**
     * Load graph data with optional pagination and filtering.
     *
     * @param {string} sessionId - The session identifier
     * @param {Object} options - Optional parameters
     * @param {number} options.offset - Number of nodes to skip (default: 0)
     * @param {number} options.limit - Maximum nodes to return (default: 500)
     * @param {string} options.nodeType - Filter by node type (optional)
     * @returns {Promise<Object>} Pagination metadata
     */
    async loadData(sessionId, options = {}) {
        const { offset = 0, limit = 500, nodeType = null } = options;

        try {
            const params = new URLSearchParams();
            params.append('offset', offset.toString());
            params.append('limit', limit.toString());
            if (nodeType) {
                params.append('node_type', nodeType);
            }

            const response = await fetch(
                '/api/graph/' + sessionId + '/visualization?' + params.toString()
            );
            const data = await response.json();

            this.setData(data.elements);
            this.pagination = data.pagination || null;

            return this.pagination;
        } catch (error) {
            console.error('Failed to load graph data:', error);
            return null;
        }
    }

    /**
     * Load more nodes (append to existing graph).
     *
     * @param {string} sessionId - The session identifier
     * @param {Object} options - Optional parameters
     * @returns {Promise<Object>} Pagination metadata
     */
    async loadMore(sessionId, options = {}) {
        if (!this.pagination || !this.pagination.has_more) {
            return this.pagination;
        }

        const nextOffset = this.pagination.offset + this.pagination.limit;
        const { limit = this.pagination.limit, nodeType = null } = options;

        try {
            const params = new URLSearchParams();
            params.append('offset', nextOffset.toString());
            params.append('limit', limit.toString());
            if (nodeType) {
                params.append('node_type', nodeType);
            }

            const response = await fetch(
                '/api/graph/' + sessionId + '/visualization?' + params.toString()
            );
            const data = await response.json();

            // Append new elements instead of replacing
            if (this.cy) {
                this.cy.add(data.elements.nodes || []);
                this.cy.add(data.elements.edges || []);

                // Re-run layout to incorporate new nodes
                this.cy.layout({
                    name: 'cose',
                    animate: true,
                    randomize: false,
                    nodeDimensionsIncludeLabels: true,
                    fit: false,
                }).run();
            }

            this.pagination = data.pagination || null;
            return this.pagination;
        } catch (error) {
            console.error('Failed to load more graph data:', error);
            return null;
        }
    }

    /**
     * Get current pagination state.
     *
     * @returns {Object|null} Pagination metadata or null
     */
    getPagination() {
        return this.pagination;
    }

    setData(elements) {
        if (!this.cy) return;

        this.cy.elements().remove();
        this.cy.add(elements.nodes || []);
        this.cy.add(elements.edges || []);

        this.cy.layout({
            name: 'cose',
            animate: true,
            randomize: false,
            nodeDimensionsIncludeLabels: true,
        }).run();
    }

    highlightPath(pathNodes) {
        if (!this.cy) return;

        this.cy.elements().removeClass('highlighted');

        pathNodes.forEach(function(nodeId) {
            const node = this.cy.getElementById(nodeId);
            if (node) {
                node.addClass('highlighted');
            }
        }, this);
    }

    fitToView() {
        if (this.cy) {
            this.cy.fit();
        }
    }

    destroy() {
        if (this.cy) {
            this.cy.destroy();
            this.cy = null;
        }
        this.pagination = null;
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = AriadneGraph;
}
