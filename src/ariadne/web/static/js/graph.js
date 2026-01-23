/**
 * Ariadne Graph Visualization
 * Uses Cytoscape.js for interactive graph rendering
 */

class AriadneGraph {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.cy = null;
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

    async loadData(sessionId) {
        try {
            const response = await fetch('/api/graph/' + sessionId + '/visualization');
            const data = await response.json();
            this.setData(data.elements);
        } catch (error) {
            console.error('Failed to load graph data:', error);
        }
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
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = AriadneGraph;
}
