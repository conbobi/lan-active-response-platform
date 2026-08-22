// src/components/network/NetworkTopology3D.jsx
import React, { useRef, useMemo, useCallback } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import * as THREE from 'three';

const TYPE_COLORS = {
  gateway: '#3b82f6',
  firewall: '#f97316',
  analyzer: '#a855f7',
  sensor: '#06b6d4',
  server: '#f59e0b',
  endpoint: '#10b981',
};

export default function NetworkTopology3D({
  agents = [],
  links = [],
  pathData = null,
  onNodeClick,
  onLinkClick,
  fgRef,
}) {
  // Format graph data for ForceGraph3D
  const graphData = useMemo(() => {
    const nodes = agents.map((a) => ({
      id: a.id,
      name: a.name,
      type: a.type,
      ip: a.ip,
      status: a.status,
      color: TYPE_COLORS[a.type] || '#6100ff',
    }));

    const formattedLinks = links.map((l) => {
      const isPathLink = pathData?.linkIds?.includes(l.id);
      return {
        id: l.id,
        source: l.source.id || l.source,
        target: l.target.id || l.target,
        latency: l.latency,
        bandwidth: l.bandwidth,
        isActive: l.isActive,
        isPathLink: Boolean(isPathLink),
      };
    });

    return { nodes, links: formattedLinks };
  }, [agents, links, pathData]);

  // Create custom 3D node object (Sphere + Sprite label)
  const createNodeObject = useCallback((node) => {
    const group = new THREE.Group();

    // Node Sphere Mesh
    const geometry = new THREE.SphereGeometry(6, 24, 24);
    const material = new THREE.MeshLambertMaterial({
      color: node.color,
      transparent: true,
      opacity: node.status === 'offline' ? 0.4 : 0.9,
    });
    const sphere = new THREE.Mesh(geometry, material);
    group.add(sphere);

    // Glowing outer ring for online nodes
    if (node.status !== 'offline') {
      const glowGeo = new THREE.SphereGeometry(7.2, 16, 16);
      const glowMat = new THREE.MeshBasicMaterial({
        color: node.color,
        transparent: true,
        opacity: 0.25,
      });
      const glowMesh = new THREE.Mesh(glowGeo, glowMat);
      group.add(glowMesh);
    }

    // Text Label Sprite above node
    const canvas = document.createElement('canvas');
    canvas.width = 256;
    canvas.height = 64;
    const ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.fillStyle = node.status === 'offline' ? '#94a3b8' : '#ffffff';
      ctx.font = 'Bold 24px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.shadowColor = 'rgba(0,0,0,0.8)';
      ctx.shadowBlur = 4;
      ctx.fillText(node.name, 128, 40);
    }

    const texture = new THREE.CanvasTexture(canvas);
    const spriteMaterial = new THREE.SpriteMaterial({ map: texture, transparent: true });
    const sprite = new THREE.Sprite(spriteMaterial);
    sprite.scale.set(24, 6, 1);
    sprite.position.set(0, 10, 0);
    group.add(sprite);

    return group;
  }, []);

  // Custom link color mapping
  const getLinkColor = useCallback((link) => {
    if (link.isPathLink) return '#ffab00'; // Gold highlighted path
    if (!link.isActive) return '#ef4444'; // Red broken link
    return '#6100ff'; // SentinelOne violet active link
  }, []);

  // Link width
  const getLinkWidth = useCallback((link) => {
    if (link.isPathLink) return 3.5;
    if (!link.isActive) return 1;
    return 1.8;
  }, []);

  // Link particles for highlighted paths
  const getLinkParticles = useCallback((link) => {
    if (link.isPathLink) return 4;
    if (link.isActive) return 1;
    return 0;
  }, []);

  const getLinkParticleSpeed = useCallback((link) => {
    if (link.isPathLink) return 0.012;
    return 0.005;
  }, []);

  return (
    <div
      style={{
        width: '100%',
        height: '560px',
        position: 'relative',
        borderRadius: 'var(--radius-md)',
        overflow: 'hidden',
        background: 'radial-gradient(circle at center, #13152c 0%, #090a14 100%)',
        boxShadow: 'var(--shadow-md)',
        border: '1px solid var(--border)',
      }}
    >
      <ForceGraph3D
        ref={fgRef}
        graphData={graphData}
        nodeThreeObject={createNodeObject}
        nodeLabel={(node) => `
          <div style="background: rgba(13,14,26,0.95); padding: 8px 12px; border-radius: 6px; border: 1px solid #6100ff; color: #fff; font-family: sans-serif; font-size: 12px;">
            <strong style="color: ${node.color}">${node.name}</strong><br/>
            IP: ${node.ip}<br/>
            Type: ${node.type.toUpperCase()}<br/>
            Status: <span style="color: ${node.status === 'online' ? '#00c07b' : '#ef4444'}">${node.status.toUpperCase()}</span>
          </div>
        `}
        linkLabel={(link) => `
          <div style="background: rgba(13,14,26,0.95); padding: 6px 10px; border-radius: 6px; border: 1px solid #4a5568; color: #fff; font-family: sans-serif; font-size: 11px;">
            Link ID: ${link.id}<br/>
            Latency: <strong>${link.latency} ms</strong><br/>
            Bandwidth: <strong>${link.bandwidth} Mbps</strong><br/>
            Status: <span style="color: ${link.isActive ? '#00c07b' : '#ef4444'}">${link.isActive ? 'ACTIVE' : 'BROKEN'}</span>
          </div>
        `}
        linkColor={getLinkColor}
        linkWidth={getLinkWidth}
        linkDirectionalParticles={getLinkParticles}
        linkDirectionalParticleSpeed={getLinkParticleSpeed}
        linkDirectionalParticleWidth={3}
        linkDirectionalParticleColor={() => '#ffab00'}
        onNodeClick={(node) => onNodeClick && onNodeClick(node)}
        onLinkClick={(link) => onLinkClick && onLinkClick(link)}
        showNavInfo={false}
        enableNodeDrag={true}
        backgroundColor="rgba(0,0,0,0)"
      />

      {/* 3D Legend overlay */}
      <div
        style={{
          position: 'absolute',
          bottom: 12,
          left: 12,
          background: 'rgba(13,14,26,0.85)',
          backdropFilter: 'blur(8px)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-sm)',
          padding: '0.6rem 0.8rem',
          display: 'flex',
          gap: '0.75rem',
          alignItems: 'center',
          fontSize: '0.75rem',
          color: '#e2e8f0',
          pointerEvents: 'none',
        }}
      >
        {Object.entries(TYPE_COLORS).map(([type, color]) => (
          <div key={type} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: color }} />
            <span style={{ textTransform: 'capitalize' }}>{type}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
