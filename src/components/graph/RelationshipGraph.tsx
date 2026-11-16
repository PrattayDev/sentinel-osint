'use client';

import React, { useMemo, useState } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  MarkerType
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { EntityRecord, EntityRelationshipRecord, EntityType } from '@/types/osint';
import {
  Download,
  Filter,
  Network,
  Search,
  ShieldCheck,
  Sparkles
} from 'lucide-react';

interface RelationshipGraphProps {
  entities: EntityRecord[];
  relationships: EntityRelationshipRecord[];
  onInvestigateEntity?: (entity: EntityRecord) => void;
}

const ENTITY_COLORS: Record<EntityType, string> = {
  domain: '#06b6d4',
  ip: '#3b82f6',
  asn: '#8b5cf6',
  url: '#10b981',
  profile: '#f59e0b',
  organization: '#ec4899',
  email: '#14b8a6',
  file_hash: '#f43f5e',
  certificate: '#eab308',
  phone: '#6366f1',
  evidence_source: '#64748b'
};

export function RelationshipGraph({
  entities,
  relationships,
  onInvestigateEntity
}: RelationshipGraphProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [selectedEntity, setSelectedEntity] = useState<EntityRecord | null>(null);

  const filteredEntities = useMemo(() => {
    return entities.filter((e) => {
      const matchesType = typeFilter === 'all' || e.entityType === typeFilter;
      const matchesSearch =
        !searchTerm.trim() ||
        e.label.toLowerCase().includes(searchTerm.toLowerCase()) ||
        e.value.toLowerCase().includes(searchTerm.toLowerCase());
      return matchesType && matchesSearch;
    });
  }, [entities, typeFilter, searchTerm]);

  const visibleIds = useMemo(
    () => new Set(filteredEntities.map((e) => e.id)),
    [filteredEntities]
  );

  const nodes: Node[] = useMemo(() => {
    return filteredEntities.map((e, idx) => {
      const angle = (idx * 2 * Math.PI) / Math.max(6, filteredEntities.length);
      const radius = 180 + Math.floor(idx / 8) * 110;
      const x = e.positionX ?? Math.round(380 + radius * Math.cos(angle));
      const y = e.positionY ?? Math.round(240 + radius * Math.sin(angle));
      const borderColor = ENTITY_COLORS[e.entityType] || '#06b6d4';

      return {
        id: e.id,
        position: { x, y },
        data: {
          label: (
            <div className="text-left">
              <div className="flex items-center justify-between gap-2 text-[10px] uppercase tracking-wider font-mono text-cyan-400">
                <span>{e.entityType}</span>
                <span className="text-slate-400">{e.confidence}</span>
              </div>
              <div className="font-semibold text-xs text-slate-100 truncate max-w-[180px] mt-0.5">
                {e.label}
              </div>
              <div className="text-[10px] text-slate-400 truncate max-w-[180px]">
                via {e.providerId}
              </div>
            </div>
          )
        },
        style: {
          background: '#0d1424',
          color: '#f8fafc',
          border: `1.5px solid ${borderColor}`,
          borderRadius: '8px',
          padding: '8px 10px',
          minWidth: '170px',
          boxShadow: '0 4px 20px rgba(0,0,0,0.45)'
        }
      };
    });
  }, [filteredEntities]);

  const edges: Edge[] = useMemo(() => {
    return relationships
      .filter(
        (r) =>
          visibleIds.has(r.sourceEntityId) && visibleIds.has(r.targetEntityId)
      )
      .map((r) => ({
        id: r.id,
        source: r.sourceEntityId,
        target: r.targetEntityId,
        label: `${r.relationshipType} (${r.confidence})`,
        animated: r.confidence === 'confirmed',
        style: {
          stroke: r.confidence === 'confirmed' ? '#06b6d4' : '#64748b',
          strokeWidth: 1.5
        },
        labelStyle: {
          fill: '#cbd5e1',
          fontSize: 10,
          fontFamily: 'monospace'
        },
        labelBgStyle: {
          fill: '#070b14',
          fillOpacity: 0.85
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: r.confidence === 'confirmed' ? '#06b6d4' : '#64748b'
        }
      }));
  }, [relationships, visibleIds]);

  const handleExportGraphJson = () => {
    const payload = {
      exportedAt: new Date().toISOString(),
      platform: 'Sentinel OSINT Graph Service',
      nodeCount: filteredEntities.length,
      edgeCount: edges.length,
      entities: filteredEntities,
      relationships: relationships.filter(
        (r) =>
          visibleIds.has(r.sourceEntityId) && visibleIds.has(r.targetEntityId)
      )
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: 'application/json'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-graph-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportGraphSvg = () => {
    const svgHeader = `<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="650" viewBox="0 0 1000 650" style="background:#070b14;font-family:monospace">`;
    const nodeMap = new Map(nodes.map((n) => [n.id, n.position]));
    const edgeLines = edges
      .map((e) => {
        const s = nodeMap.get(e.source);
        const t = nodeMap.get(e.target);
        if (!s || !t) return '';
        return `<line x1="${s.x + 80}" y1="${s.y + 25}" x2="${t.x + 80}" y2="${t.y + 25}" stroke="#06b6d4" stroke-width="1.5" />`;
      })
      .join('\n');
    const nodeBoxes = filteredEntities
      .map((ent, idx) => {
        const pos = nodes[idx]?.position || { x: 100, y: 100 };
        const safeLabel = ent.label.replace(/[<>&"']/g, '');
        return `<g transform="translate(${pos.x},${pos.y})"><rect width="170" height="48" rx="6" fill="#0d1424" stroke="#06b6d4" /><text x="10" y="18" fill="#06b6d4" font-size="10">${ent.entityType.toUpperCase()} (${ent.confidence})</text><text x="10" y="36" fill="#f8fafc" font-size="11">${safeLabel.slice(0, 22)}</text></g>`;
      })
      .join('\n');
    const svgContent = `${svgHeader}\n${edgeLines}\n${nodeBoxes}\n</svg>`;
    const blob = new Blob([svgContent], { type: 'image/svg+xml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-graph-${Date.now()}.svg`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900/90 border border-slate-800 rounded-xl p-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter entities by value or label..."
              className="pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200"
            >
              <option value="all">All Entity Types ({entities.length})</option>
              <option value="domain">Domain</option>
              <option value="ip">IP Address</option>
              <option value="asn">ASN</option>
              <option value="url">URL</option>
              <option value="profile">Public Profile</option>
              <option value="organization">Organization</option>
              <option value="email">Email</option>
              <option value="file_hash">File Hash</option>
              <option value="certificate">Certificate</option>
              <option value="phone">Phone</option>
            </select>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleExportGraphJson}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 border border-slate-700"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            Export Graph JSON
          </button>
          <button
            type="button"
            onClick={handleExportGraphSvg}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 text-xs text-cyan-300 border border-cyan-500/30"
          >
            <Download className="w-3.5 h-3.5" />
            Export Graph Image (SVG)
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3 h-[540px] bg-slate-950 border border-slate-800 rounded-xl overflow-hidden relative">
          {filteredEntities.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-slate-400 p-6 text-center">
              <Network className="w-10 h-10 text-cyan-500/50 mb-2" />
              <p className="text-sm font-medium text-slate-200">
                No Graph Entities Matching Current View
              </p>
              <p className="text-xs text-slate-400 mt-1 max-w-md">
                Run a Universal Search or module lookup (Domain, IP, Email, Username, or Organization) to populate corroborated entity nodes and relationships.
              </p>
            </div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              fitView
              onNodeClick={(_, node) => {
                const found = entities.find((e) => e.id === node.id) || null;
                setSelectedEntity(found);
              }}
            >
              <Background color="#1e293b" gap={20} />
              <Controls />
              <MiniMap
                nodeColor="#06b6d4"
                maskColor="rgba(7, 11, 20, 0.75)"
                style={{ backgroundColor: '#0d1424' }}
              />
            </ReactFlow>
          )}
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
          {selectedEntity ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="text-xs font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                  {selectedEntity.entityType}
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  Confidence: {selectedEntity.confidence}
                </span>
              </div>
              <div>
                <div className="text-xs text-slate-400">Entity Label</div>
                <div className="text-sm font-semibold text-white break-all mt-0.5">
                  {selectedEntity.label}
                </div>
              </div>
              <div>
                <div className="text-xs text-slate-400">Canonical Value</div>
                <div className="text-xs font-mono text-cyan-300 break-all mt-0.5">
                  {selectedEntity.value}
                </div>
              </div>
              <div>
                <div className="text-xs text-slate-400">Source Provider</div>
                <div className="text-xs text-slate-200 mt-0.5">
                  {selectedEntity.providerId}
                </div>
              </div>
              <div>
                <div className="text-xs text-slate-400">Observed Timestamp</div>
                <div className="text-xs font-mono text-slate-300 mt-0.5">
                  {selectedEntity.observedAt}
                </div>
              </div>
              {Object.keys(selectedEntity.metadata || {}).length > 0 && (
                <div>
                  <div className="text-xs text-slate-400 mb-1">
                    Provenance Metadata
                  </div>
                  <pre className="text-[11px] font-mono bg-slate-950 p-2 rounded border border-slate-800 overflow-x-auto text-slate-300 max-h-40">
                    {JSON.stringify(selectedEntity.metadata, null, 2)}
                  </pre>
                </div>
              )}

              {onInvestigateEntity &&
                ['domain', 'ip', 'url', 'email', 'organization', 'file_hash'].includes(
                  selectedEntity.entityType
                ) && (
                  <button
                    type="button"
                    onClick={() => onInvestigateEntity(selectedEntity)}
                    className="w-full mt-2 inline-flex items-center justify-center gap-1.5 px-3 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs transition"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    Pivot & Investigate This Entity
                  </button>
                )}
            </div>
          ) : (
            <div className="text-xs text-slate-400 space-y-2">
              <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-cyan-400" />
                Entity Provenance Inspector
              </div>
              <p>
                Click any node in the graph to inspect its originating OSINT provider, observation timestamp, confidence classification, and pivot options.
              </p>
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-[11px] text-slate-400 mt-3">
                <strong className="text-slate-200 block mb-1">
                  Non-Inferential Graph Policy
                </strong>
                Coincidental username matches are labeled with low confidence and never automatically merged into personal identity nodes.
              </div>
            </div>
          )}

          <div className="pt-3 border-t border-slate-800 text-[11px] text-slate-400 flex justify-between">
            <span>Nodes: {filteredEntities.length}</span>
            <span>Edges: {edges.length}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
