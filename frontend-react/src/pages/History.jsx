import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { analysis } from '../services/api';
import Card from '../components/Card';
import Badge from '../components/Badge';
import Button from '../components/Button';
import LoadingState from '../components/LoadingState';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';
import {
  History as HistoryIcon,
  Search,
  Filter,
  ShieldAlert,
  RefreshCw,
  ArrowRight,
  ChevronRight,
  X,
  SlidersHorizontal,
  Clock,
  Layers,
  Activity,
  ShieldCheck,
  AlertTriangle,
} from 'lucide-react';

/**
 * Maps risk level to badge variants
 */
const getRiskBadgeVariant = (level) => {
  const norm = String(level || '').toUpperCase();
  if (norm === 'CRITICAL' || norm === 'HIGH') return 'danger';
  if (norm === 'MEDIUM') return 'warning';
  if (norm === 'LOW') return 'success';
  return 'neutral';
};

/**
 * Format timestamp safely
 */
const formatDateTime = (isoString) => {
  if (!isoString) return '—';
  try {
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return '—';
    return date.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return '—';
  }
};

const History = () => {
  const navigate = useNavigate();

  const [historyData, setHistoryData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [limit, setLimit] = useState(50);

  // Filter & Search states
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState('ALL');
  const [selectedRisk, setSelectedRisk] = useState('ALL');

  const fetchHistory = async (fetchLimit = limit) => {
    setLoading(true);
    setError(null);
    try {
      const data = await analysis.history(fetchLimit);
      setHistoryData(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err?.message || 'Failed to retrieve investigation history from the security server.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory(limit);
  }, [limit]);

  // Client-side filtering on fetched records
  const filteredRecords = useMemo(() => {
    return historyData.filter((item) => {
      // 1. Search term match (by ID or target)
      if (searchTerm.trim()) {
        const query = searchTerm.trim().toLowerCase();
        const idMatch = String(item.id).includes(query.replace(/^#/, ''));
        const targetMatch = String(item.url || '').toLowerCase().includes(query);
        const typeMatch = String(item.artifact_type || '').toLowerCase().includes(query);
        if (!idMatch && !targetMatch && !typeMatch) {
          return false;
        }
      }

      // 2. Artifact type match
      if (selectedType !== 'ALL') {
        if (String(item.artifact_type || '').toUpperCase() !== selectedType) {
          return false;
        }
      }

      // 3. Risk level match
      if (selectedRisk !== 'ALL') {
        const itemRisk = String(item.risk_level || '').toUpperCase();
        if (selectedRisk === 'HIGH_CRITICAL') {
          if (itemRisk !== 'HIGH' && itemRisk !== 'CRITICAL') return false;
        } else if (itemRisk !== selectedRisk) {
          return false;
        }
      }

      return true;
    });
  }, [historyData, searchTerm, selectedType, selectedRisk]);

  const hasActiveFilters = searchTerm.trim() !== '' || selectedType !== 'ALL' || selectedRisk !== 'ALL';

  const clearFilters = () => {
    setSearchTerm('');
    setSelectedType('ALL');
    setSelectedRisk('ALL');
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      {/* 1. Page Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-3 border-b border-slate-200 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <HistoryIcon size={24} className="text-blue-600 dark:text-blue-400" />
              <span>Investigation History</span>
            </h1>
            <span className="px-2 py-0.5 text-xs font-semibold rounded-md bg-blue-100 text-blue-800 dark:bg-blue-900/60 dark:text-blue-300">
              Audit Trail
            </span>
          </div>
          <p className="text-xs md:text-sm text-slate-500 dark:text-slate-400">
            Review previous PHISHGUARD forensic investigations, multi-layer risk scores, and telemetry records.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <Button
            variant="secondary"
            onClick={() => fetchHistory(limit)}
            disabled={loading}
            className="flex items-center gap-1.5 text-xs py-2 px-3"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </Button>
          <Button
            variant="primary"
            onClick={() => navigate('/analyze')}
            className="flex items-center gap-1.5 text-xs py-2 px-3"
          >
            <ShieldAlert size={14} />
            <span>New Analysis</span>
          </Button>
        </div>
      </div>

      {/* 2. Filter & Search Controls */}
      <Card className="p-4 border border-slate-200 dark:border-slate-800 shadow-sm space-y-3">
        <div className="flex flex-col md:flex-row items-center justify-between gap-3">
          {/* Search Input */}
          <div className="relative w-full md:w-80">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
              <Search size={16} />
            </div>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by ID, URL, or target..."
              className="w-full pl-9 pr-8 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 text-xs placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
            />
            {searchTerm && (
              <button
                type="button"
                onClick={() => setSearchTerm('')}
                className="absolute inset-y-0 right-0 pr-2.5 flex items-center text-slate-400 hover:text-slate-600"
              >
                <X size={14} />
              </button>
            )}
          </div>

          {/* Type & Risk Selectors */}
          <div className="flex items-center gap-2.5 w-full md:w-auto flex-wrap">
            {/* Artifact Type Filter */}
            <div className="flex items-center gap-1.5 text-xs">
              <span className="text-slate-500 dark:text-slate-400 font-medium">Type:</span>
              <select
                value={selectedType}
                onChange={(e) => setSelectedType(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="ALL">All Types</option>
                <option value="URL">URL</option>
                <option value="HASH">Hash</option>
                <option value="EMAIL">Email</option>
                <option value="QR">QR Code</option>
                <option value="FILE">File</option>
              </select>
            </div>

            {/* Risk Level Filter */}
            <div className="flex items-center gap-1.5 text-xs">
              <span className="text-slate-500 dark:text-slate-400 font-medium">Risk:</span>
              <select
                value={selectedRisk}
                onChange={(e) => setSelectedRisk(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 text-xs font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="ALL">All Risk Levels</option>
                <option value="HIGH_CRITICAL">High & Critical</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low / Benign</option>
              </select>
            </div>

            {/* Reset Filters */}
            {hasActiveFilters && (
              <Button
                variant="secondary"
                onClick={clearFilters}
                className="text-xs py-1.5 px-2 text-slate-500 hover:text-slate-800 dark:text-slate-400"
              >
                Reset
              </Button>
            )}
          </div>
        </div>
      </Card>

      {/* Error State */}
      {error && (
        <ErrorState
          title="History Synchronization Error"
          message={error}
          onRetry={() => fetchHistory(limit)}
        />
      )}

      {/* 3. History Table Container */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-sm overflow-hidden">
        {loading ? (
          <div className="py-16">
            <LoadingState message="Loading your investigation records…" />
          </div>
        ) : historyData.length === 0 ? (
          <EmptyState
            title="No investigations yet"
            description="You have not submitted any URLs, hashes, emails, QR codes, or files for inspection yet."
            action={
              <Button onClick={() => navigate('/analyze')} variant="primary" className="text-xs">
                Start an Analysis
              </Button>
            }
          />
        ) : filteredRecords.length === 0 ? (
          <div className="py-12 text-center space-y-3">
            <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">
              No investigations match your active filters.
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mx-auto">
              Try adjusting your search keyword, artifact type, or risk level filter.
            </p>
            <Button variant="secondary" onClick={clearFilters} className="text-xs">
              Clear Filters
            </Button>
          </div>
        ) : (
          <div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm" aria-label="Investigation History">
                <thead className="bg-slate-50 dark:bg-slate-800/50 text-slate-500 dark:text-slate-400 text-xs font-semibold uppercase border-b border-slate-200 dark:border-slate-800">
                  <tr>
                    <th scope="col" className="px-4 py-3">Analysis ID</th>
                    <th scope="col" className="px-4 py-3">Artifact</th>
                    <th scope="col" className="px-4 py-3">Target / Target Identifier</th>
                    <th scope="col" className="px-4 py-3">Risk Score</th>
                    <th scope="col" className="px-4 py-3">Risk Level</th>
                    <th scope="col" className="px-4 py-3">Created</th>
                    <th scope="col" className="px-4 py-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-slate-700 dark:text-slate-300">
                  {filteredRecords.map((item) => {
                    const riskVariant = getRiskBadgeVariant(item.risk_level);
                    return (
                      <tr
                        key={item.id}
                        className="hover:bg-slate-50/80 dark:hover:bg-slate-800/40 transition-colors"
                      >
                        <td className="px-4 py-3 font-mono text-xs font-bold text-slate-500">
                          #{item.id}
                        </td>
                        <td className="px-4 py-3">
                          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 uppercase">
                            {item.artifact_type || 'URL'}
                          </span>
                        </td>
                        <td
                          className="px-4 py-3 font-mono text-xs max-w-sm truncate text-slate-900 dark:text-slate-100 font-medium"
                          title={item.url || '—'}
                        >
                          {item.url || '—'}
                        </td>
                        <td className="px-4 py-3 text-xs font-bold">
                          <span
                            className={
                              item.risk_score >= 70
                                ? 'text-red-600 dark:text-red-400'
                                : item.risk_score >= 40
                                ? 'text-amber-600 dark:text-amber-400'
                                : 'text-emerald-600 dark:text-emerald-400'
                            }
                          >
                            {typeof item.risk_score === 'number'
                              ? `${Math.round(item.risk_score)}/100`
                              : '—'}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <Badge variant={riskVariant}>
                            {item.risk_level || 'UNKNOWN'}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
                          {formatDateTime(item.created_at)}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <Button
                            variant="secondary"
                            onClick={() => navigate(`/analysis/${item.id}`)}
                            className="px-3 py-1 text-xs font-semibold"
                          >
                            View
                          </Button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Table Footer: Results count & optional Load More */}
            <div className="px-4 py-3 bg-slate-50/50 dark:bg-slate-800/30 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-xs text-slate-500">
              <span>
                Showing {filteredRecords.length} of {historyData.length} records
              </span>

              {historyData.length >= limit && limit < 100 && (
                <button
                  type="button"
                  onClick={() => setLimit(100)}
                  className="font-semibold text-blue-600 dark:text-blue-400 hover:underline"
                >
                  Load up to 100 records
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default History;
