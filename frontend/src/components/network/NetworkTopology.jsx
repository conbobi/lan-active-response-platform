// src/components/network/NetworkTopology.jsx
import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { fetchTopology, findPath, simulateFailure } from '../api/network';
import Button from '../components/ui/Button';
import Dropdown from '../components/ui/Dropdown';
import { FiRefreshCw, FiZap, FiAlertTriangle } from 'react-icons/fi';

cytoscape.use(dagre);

export default function NetworkTopology() {
    const containerRef = useRef(null);
    const [cy, setCy] = useState(null);
    const [links, setLinks] = useState([]);
    const [selectedFrom, setSelectedFrom] = useState('');
    const [selectedTo, setSelectedTo] = useState('');
    const [loading, setLoading] = useState(false);
    const [isDark, setIsDark] = useState(false);

    // Lấy dữ liệu topology
    useEffect(() => {
        loadTopology();
    }, []);

    const loadTopology = async () => {
        setLoading(true);
        const data = await fetchTopology();
        setLinks(data);
        renderGraph(data);
        setLoading(false);
    };

    const renderGraph = (linksData) => {
        if (cy) cy.destroy();

        const elements = [];
        const nodes = new Set();
        linksData.forEach(link => {
            if (link.isActive) {
                nodes.add(link.sourceAgentId);
                nodes.add(link.targetAgentId);
            }
        });
        // Thêm node
        nodes.forEach(nodeId => {
            elements.push({
                data: { id: nodeId, label: nodeId.substring(0, 8) }
            });
        });
        // Thêm edge
        linksData.forEach(link => {
            elements.push({
                data: {
                    id: link.id,
                    source: link.sourceAgentId,
                    target: link.targetAgentId,
                    weight: link.latency,
                    active: link.isActive,
                }
            });
        });

        const cyInstance = cytoscape({
            container: containerRef.current,
            elements: elements,
            style: getStyles(),
            layout: {
                name: 'dagre',
                rankDir: 'TB',
                spacingFactor: 1.5,
                animate: true,
            }
        });

        // Animation: di chuyển đường đi
        cyInstance.on('tap', 'edge', function (evt) {
            const edge = evt.target;
            edge.animate({
                style: { 'line-color': '#ffab00', 'width': 4 }
            }, { duration: 300 });
            setTimeout(() => {
                edge.animate({
                    style: { 'line-color': edge.data('active') ? '#00aa5b' : '#ccc', 'width': 2 }
                }, { duration: 300 });
            }, 1500);
        });

        setCy(cyInstance);
    };

    const getStyles = () => [
        {
            selector: 'node',
            style: {
                'background-color': '#6100ff',
                'label': 'data(label)',
                'color': '#ffffff',
                'font-size': '12px',
                'font-weight': '600',
                'text-valign': 'center',
                'text-halign': 'center',
                'width': 50,
                'height': 50,
                'border-width': 2,
                'border-color': '#e0e0e0',
                'shadow-blur': 10,
                'shadow-color': 'rgba(97,0,255,0.3)',
                'shadow-offset-x': 0,
                'shadow-offset-y': 4,
            }
        },
        {
            selector: 'node:active',
            style: {
                'background-color': '#6841ea',
                'shadow-blur': 20,
            }
        },
        {
            selector: 'edge',
            style: {
                'width': 2,
                'line-color': '#ccc',
                'target-arrow-color': '#ccc',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                'label': 'data(weight)',
                'font-size': '10px',
                'color': '#999',
                'text-rotation': 'autorotate',
            }
        },
        {
            selector: 'edge[active = "true"]',
            style: {
                'line-color': '#00aa5b',
                'target-arrow-color': '#00aa5b',
            }
        },
        {
            selector: 'edge[active = "false"]',
            style: {
                'line-color': '#ff6b6b',
                'target-arrow-color': '#ff6b6b',
                'opacity': 0.4,
                'line-style': 'dashed',
            }
        },
        {
            selector: 'edge.highlighted',
            style: {
                'line-color': '#ffab00',
                'target-arrow-color': '#ffab00',
                'width': 4,
                'opacity': 1,
            }
        },
        {
            selector: 'edge.flowing',
            style: {
                'line-color': '#6100ff',
                'target-arrow-color': '#6100ff',
                'width': 3,
                'opacity': 0.8,
                'line-style': 'solid',
            }
        }
    ];

    // Highlight đường đi
    const highlightPath = async () => {
        if (!cy || !selectedFrom || !selectedTo) return;
        cy.elements().removeClass('highlighted');

        const result = await findPath(selectedFrom, selectedTo);
        if (result.pathLinks) {
            result.pathLinks.forEach(linkId => {
                cy.getElementById(linkId).addClass('highlighted');
            });
        }
    };

    // Mô phỏng lỗi link
    const simulateLinkFailure = async (linkId) => {
        await simulateFailure(linkId);
        await loadTopology();
    };

    // Tạo hiệu ứng flow trên đường đi
    const animateFlow = (pathLinks) => {
        if (!cy) return;
        cy.elements().removeClass('flowing');
        pathLinks.forEach((linkId, index) => {
            setTimeout(() => {
                cy.getElementById(linkId).addClass('flowing');
            }, index * 300);
        });
        setTimeout(() => {
            cy.elements().removeClass('flowing');
        }, pathLinks.length * 300 + 1000);
    };

    // Lấy danh sách agent id từ link
    const agentOptions = [...new Set(links.flatMap(l => [l.sourceAgentId, l.targetAgentId]))]
        .filter(Boolean)
        .map(id => ({ value: id, label: id.substring(0, 12) }));

    return (
        <div className="network-topology">
            <div className="network-toolbar">
                <div className="network-controls">
                    <Dropdown
                        label="From"
                        options={agentOptions}
                        value={selectedFrom}
                        onChange={setSelectedFrom}
                        placeholder="Source Agent"
                    />
                    <Dropdown
                        label="To"
                        options={agentOptions}
                        value={selectedTo}
                        onChange={setSelectedTo}
                        placeholder="Target Agent"
                    />
                    <Button variant="primary" size="sm" iconLeft={<FiZap />} onClick={highlightPath}>
                        Find Path
                    </Button>
                    <Button variant="secondary" size="sm" iconLeft={<FiRefreshCw />} onClick={loadTopology}>
                        Refresh
                    </Button>
                </div>
                <div className="network-status">
                    <span className="status-dot active" /> {links.filter(l => l.isActive).length} Active
                    <span className="status-dot inactive" style={{ marginLeft: '1rem' }} /> {links.filter(l => !l.isActive).length} Inactive
                </div>
            </div>
            <div ref={containerRef} style={{ width: '100%', height: '600px', background: isDark ? '#1a1a2e' : '#f8f9fc', borderRadius: '12px' }} />
        </div>
    );
}