<script lang="ts" setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';

import { Page } from 'shell/vben/common-ui';
import { $t } from 'shell/locales';

import { Alert, Card, Col, Empty, Row, Segmented, Spin, Statistic } from 'ant-design-vue';
import VChart from 'vue-echarts';
import { use } from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import { LineChart, PieChart } from 'echarts/charts';
import {
  GridComponent,
  LegendComponent,
  TitleComponent,
  TooltipComponent,
} from 'echarts/components';

import { DashboardService, type InstantSample, type RangeSeries } from '../../api/services';
import { formatTime } from '../../utils/format';

use([
  CanvasRenderer,
  LineChart,
  PieChart,
  GridComponent,
  LegendComponent,
  TitleComponent,
  TooltipComponent,
]);

// 30-second refresh roughly matches Prometheus's default scrape rate
// (15s) with one cycle of slack so the page never shows stale data.
const REFRESH_MS = 30_000;

// Time-window presets. `rangeMs` is the lookback for the time-series
// charts; `stepSeconds` is chosen so the chart renders ~60 datapoints.
interface WindowPreset {
  key: string;
  label: string;
  rangeMs: number;
  stepSeconds: number;
}

const WINDOWS: WindowPreset[] = [
  { key: '1h', label: '1h', rangeMs: 60 * 60_000, stepSeconds: 60 },
  { key: '6h', label: '6h', rangeMs: 6 * 60 * 60_000, stepSeconds: 360 },
  { key: '24h', label: '24h', rangeMs: 24 * 60 * 60_000, stepSeconds: 1440 },
];

const windowKey = ref<string>('1h');
const activeWindow = computed<WindowPreset>(
  () => WINDOWS.find((w) => w.key === windowKey.value) ?? WINDOWS[0],
);

// 503 PROMETHEUS_DISABLED → show the dedicated "not configured" Alert
// instead of a generic error banner.
function isPromDisabled(message: string): boolean {
  return /PROMETHEUS_DISABLED/i.test(message);
}

interface DashboardSnapshot {
  // Recursor headline counters.
  recQuestionsPerSec?: number;
  recCacheHitRatio?: number; // percent 0..100
  recConcurrent?: number;
  recUptime?: number; // seconds
  // Authoritative headline counters.
  authBackendQps?: number;
  authPacketCacheRatio?: number; // percent
  authQueryCacheRatio?: number; // percent
  // Pie source.
  recLatencyBuckets: InstantSample[];
}

const loading = ref(false);
const error = ref<string>('');
const promDisabled = ref(false);
const lastUpdated = ref<Date | null>(null);

const snapshot = ref<DashboardSnapshot>({
  recLatencyBuckets: [],
});

// Range series, keyed per chart.
const recAnswerOutcomes = ref<RangeSeries[]>([]);
const recQueryVsOutgoing = ref<RangeSeries[]>([]);
const authBackendSeries = ref<RangeSeries[]>([]);
const authErrorSeries = ref<RangeSeries[]>([]);

let timer: ReturnType<typeof setInterval> | null = null;

function firstScalar(samples: InstantSample[] | undefined): number | undefined {
  if (!samples || samples.length === 0) return undefined;
  const s = samples[0];
  if (!s || !s.hasValue) return undefined;
  // protojson strips zero scalars, so a real 0 arrives as undefined
  // even when hasValue is true. Coerce to keep counters stable.
  return s.value ?? 0;
}

// Wrap a single instant query so a single failing panel doesn't blank
// the whole page. A 503 PROMETHEUS_DISABLED flips the dedicated flag.
async function instant(query: string): Promise<InstantSample[]> {
  try {
    const r = await DashboardService.instantQuery({ query });
    return r.series ?? [];
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (isPromDisabled(msg)) promDisabled.value = true;
    else error.value = msg;
    return [];
  }
}

async function range(query: string): Promise<RangeSeries[]> {
  const w = activeWindow.value;
  const end = new Date();
  const start = new Date(end.getTime() - w.rangeMs);
  try {
    const r = await DashboardService.rangeQuery({
      query,
      start: start.toISOString(),
      end: end.toISOString(),
      stepSeconds: w.stepSeconds,
    });
    return r.series ?? [];
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (isPromDisabled(msg)) promDisabled.value = true;
    else error.value = msg;
    return [];
  }
}

async function refresh(): Promise<void> {
  loading.value = true;
  error.value = '';
  promDisabled.value = false;
  try {
    const [
      recQuestions,
      recCacheRatio,
      recConcurrent,
      recUptime,
      authBackendQps,
      authPacketRatio,
      authQueryRatio,
      latencyBuckets,
      answerOutcomes,
      queryVsOutgoing,
      authBackend,
      authErrors,
    ] = await Promise.all([
      instant('sum(rate(pdns_recursor_questions[5m]))'),
      instant(
        '100 * sum(pdns_recursor_cache_hits) / clamp_min(sum(pdns_recursor_cache_hits + pdns_recursor_cache_misses), 1)',
      ),
      instant('pdns_recursor_concurrent_queries'),
      instant('pdns_recursor_uptime'),
      instant('rate(pdns_auth_backend_queries[5m])'),
      instant(
        '100 * pdns_auth_packetcache_hit / clamp_min(pdns_auth_packetcache_hit + pdns_auth_packetcache_miss, 1)',
      ),
      instant(
        '100 * pdns_auth_query_cache_hit / clamp_min(pdns_auth_query_cache_hit + pdns_auth_query_cache_miss, 1)',
      ),
      // Pie buckets — fetched together as separate samples below.
      Promise.all([
        instant('pdns_recursor_answers0_1'),
        instant('pdns_recursor_answers1_10'),
        instant('pdns_recursor_answers10_100'),
        instant('pdns_recursor_answers100_1000'),
      ]).then(([a, b, c, d]) => {
        const tag = (s: InstantSample[], name: string): InstantSample | null => {
          const v = s[0];
          if (!v) return null;
          return { ...v, labels: { ...v.labels, bucket: name } };
        };
        return [
          tag(a, '<1ms'),
          tag(b, '1-10ms'),
          tag(c, '10-100ms'),
          tag(d, '100ms-1s'),
        ].filter((x): x is InstantSample => x !== null);
      }),
      // Recursor answer outcomes /sec — NOERROR / NXDOMAIN / SERVFAIL.
      Promise.all([
        range('rate(pdns_recursor_noerror_answers[5m])'),
        range('rate(pdns_recursor_nxdomain_answers[5m])'),
        range('rate(pdns_recursor_servfail_answers[5m])'),
      ]).then(([n, nx, sf]) => [
        labelSeries(n, 'NOERROR'),
        labelSeries(nx, 'NXDOMAIN'),
        labelSeries(sf, 'SERVFAIL'),
      ].flat()),
      // Recursor query rate vs outgoing.
      Promise.all([
        range('sum(rate(pdns_recursor_questions[5m]))'),
        range('rate(pdns_recursor_all_outqueries[5m])'),
      ]).then(([inc, out]) => [
        labelSeries(inc, 'incoming'),
        labelSeries(out, 'outgoing'),
      ].flat()),
      // Authoritative backend queries/sec.
      range('rate(pdns_auth_backend_queries[5m])').then((s) =>
        labelSeries(s, 'backend'),
      ),
      // Authoritative error packets /sec — SERVFAIL / NXDOMAIN.
      Promise.all([
        range('rate(pdns_auth_servfail_packets[5m])'),
        range('rate(pdns_auth_nxdomain_packets[5m])'),
      ]).then(([sf, nx]) => [
        labelSeries(sf, 'SERVFAIL'),
        labelSeries(nx, 'NXDOMAIN'),
      ].flat()),
    ]);

    snapshot.value = {
      recQuestionsPerSec: firstScalar(recQuestions),
      recCacheHitRatio: firstScalar(recCacheRatio),
      recConcurrent: firstScalar(recConcurrent),
      recUptime: firstScalar(recUptime),
      authBackendQps: firstScalar(authBackendQps),
      authPacketCacheRatio: firstScalar(authPacketRatio),
      authQueryCacheRatio: firstScalar(authQueryRatio),
      recLatencyBuckets: latencyBuckets,
    };
    recAnswerOutcomes.value = answerOutcomes;
    recQueryVsOutgoing.value = queryVsOutgoing;
    authBackendSeries.value = authBackend;
    authErrorSeries.value = authErrors;
    lastUpdated.value = new Date();
  } finally {
    loading.value = false;
  }
}

// Stamp a `name` label onto each returned series so the multi-line
// chart can pick the legend text without depending on PromQL labels
// (these queries are unlabelled scalars).
function labelSeries(series: RangeSeries[], name: string): RangeSeries[] {
  if (!series || series.length === 0) return [];
  return series.map((s) => ({ ...s, labels: { ...s.labels, name } }));
}

onMounted(() => {
  refresh();
  timer = setInterval(refresh, REFRESH_MS);
});

function onWindowChange(value: string | number): void {
  windowKey.value = String(value);
  refresh();
}

onBeforeUnmount(() => {
  if (timer) clearInterval(timer);
});

// ---- formatting helpers ----

function formatRate(n?: number): string {
  if (n == null || !Number.isFinite(n)) return '—';
  return `${n.toFixed(2)} /s`;
}

function formatPct(n?: number): string {
  if (n == null || !Number.isFinite(n)) return '—';
  return `${n.toFixed(2)}%`;
}

function formatCount(n?: number): string {
  if (n == null || !Number.isFinite(n)) return '—';
  return Math.round(n).toString();
}

function formatUptime(seconds?: number): string {
  if (seconds == null || !Number.isFinite(seconds)) return '—';
  if (seconds < 60) return `${Math.round(seconds)} s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)} min`;
  if (seconds < 86_400) return `${(seconds / 3600).toFixed(1)} h`;
  return `${(seconds / 86_400).toFixed(1)} d`;
}

function ratioColor(pct?: number): string {
  if (pct == null) return '#999999';
  if (pct >= 80) return '#52C41A';
  if (pct >= 50) return '#FAAD14';
  return '#FF4D4F';
}

// ---- chart options ----

const SERIES_COLORS: Record<string, string> = {
  NOERROR: '#52C41A',
  NXDOMAIN: '#FAAD14',
  SERVFAIL: '#FF4D4F',
  incoming: '#1890FF',
  outgoing: '#722ED1',
  backend: '#1890FF',
};

const BUCKET_COLORS: Record<string, string> = {
  '<1ms': '#52C41A',
  '1-10ms': '#1890FF',
  '10-100ms': '#FAAD14',
  '100ms-1s': '#FF4D4F',
};

function multiLineOption(series: RangeSeries[], colorMap?: Record<string, string>) {
  if (!series || series.length === 0) return null;
  return {
    grid: { left: 56, right: 16, top: 24, bottom: 28 },
    tooltip: { trigger: 'axis' },
    legend: { type: 'scroll', top: 0, textStyle: { fontSize: 11 } },
    xAxis: { type: 'time' },
    yAxis: {
      type: 'value',
      minInterval: 0.001,
      axisLabel: { formatter: (v: number) => v.toFixed(2) },
    },
    series: series.map((s) => {
      const name = s.labels.name ?? '—';
      const color = colorMap?.[name];
      return {
        name,
        type: 'line',
        showSymbol: false,
        smooth: true,
        data: s.timestamps.map((t, i) => [new Date(t).getTime(), s.values[i] ?? 0]),
        areaStyle: { opacity: 0.1, color },
        lineStyle: { width: 2, color },
        itemStyle: color ? { color } : undefined,
      };
    }),
  };
}

const recAnswerOutcomesChart = computed(() =>
  multiLineOption(recAnswerOutcomes.value, SERIES_COLORS),
);
const recQueryVsOutgoingChart = computed(() =>
  multiLineOption(recQueryVsOutgoing.value, SERIES_COLORS),
);
const authBackendChart = computed(() =>
  multiLineOption(authBackendSeries.value, SERIES_COLORS),
);
const authErrorChart = computed(() =>
  multiLineOption(authErrorSeries.value, SERIES_COLORS),
);

const recLatencyPie = computed(() => {
  const data = snapshot.value.recLatencyBuckets
    .filter((s) => s.hasValue && (s.value ?? 0) > 0)
    .map((s) => {
      const bucket = s.labels.bucket ?? '?';
      return {
        value: s.value ?? 0,
        name: bucket,
        itemStyle: { color: BUCKET_COLORS[bucket] ?? '#999999' },
      };
    });
  if (data.length === 0) return null;
  return {
    tooltip: { trigger: 'item' },
    legend: {
      type: 'scroll',
      orient: 'vertical',
      right: 0,
      top: 'middle',
      textStyle: { fontSize: 11 },
    },
    series: [
      {
        type: 'pie',
        radius: ['45%', '70%'],
        center: ['35%', '50%'],
        avoidLabelOverlap: true,
        label: { show: false },
        data,
      },
    ],
  };
});
</script>

<template>
  <Page :title="$t('dns.page.dashboard.title')">
    <div style="padding: 0">
      <Spin :spinning="loading && !lastUpdated">
        <Alert
          v-if="promDisabled"
          :message="$t('dns.page.dashboard.promDisabled')"
          type="warning"
          show-icon
          style="margin-bottom: 16px"
        />
        <Alert
          v-else-if="error"
          :message="error"
          type="warning"
          show-icon
          closable
          style="margin-bottom: 16px"
        />

        <div
          style="
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 16px;
            gap: 12px;
            flex-wrap: wrap;
          "
        >
          <Segmented
            :value="windowKey"
            :options="WINDOWS.map((w) => ({ label: w.label, value: w.key }))"
            @change="onWindowChange"
          />
          <span v-if="lastUpdated" style="font-size: 12px; color: #888">
            {{ $t('dns.page.dashboard.updated') }} {{ formatTime(lastUpdated) }}
          </span>
        </div>

        <!-- ===== Recursor ===== -->
        <h3 style="margin: 0 0 12px 0">{{ $t('dns.page.dashboard.recursor') }}</h3>

        <Row :gutter="16" style="margin-bottom: 16px">
          <Col :span="6">
            <Card>
              <Statistic
                :title="$t('dns.page.dashboard.recQuestions')"
                :value="formatRate(snapshot.recQuestionsPerSec)"
              />
            </Card>
          </Col>
          <Col :span="6">
            <Card>
              <Statistic
                :title="$t('dns.page.dashboard.recCacheHit')"
                :value="formatPct(snapshot.recCacheHitRatio)"
                :value-style="{ color: ratioColor(snapshot.recCacheHitRatio) }"
              />
            </Card>
          </Col>
          <Col :span="6">
            <Card>
              <Statistic
                :title="$t('dns.page.dashboard.recConcurrent')"
                :value="formatCount(snapshot.recConcurrent)"
              />
            </Card>
          </Col>
          <Col :span="6">
            <Card>
              <Statistic
                :title="$t('dns.page.dashboard.recUptime')"
                :value="formatUptime(snapshot.recUptime)"
              />
            </Card>
          </Col>
        </Row>

        <Row :gutter="16" style="margin-bottom: 16px">
          <Col :span="12">
            <Card :title="`${$t('dns.page.dashboard.recAnswers')} (${activeWindow.label})`" size="small">
              <VChart
                v-if="recAnswerOutcomesChart"
                :option="recAnswerOutcomesChart"
                :autoresize="true"
                style="height: 260px"
              />
              <Empty v-else :description="$t('dns.page.dashboard.noData')" />
            </Card>
          </Col>
          <Col :span="12">
            <Card :title="`${$t('dns.page.dashboard.recQueryVsOut')} (${activeWindow.label})`" size="small">
              <VChart
                v-if="recQueryVsOutgoingChart"
                :option="recQueryVsOutgoingChart"
                :autoresize="true"
                style="height: 260px"
              />
              <Empty v-else :description="$t('dns.page.dashboard.noData')" />
            </Card>
          </Col>
        </Row>

        <Row :gutter="16" style="margin-bottom: 16px">
          <Col :span="12">
            <Card :title="$t('dns.page.dashboard.recLatency')" size="small">
              <VChart
                v-if="recLatencyPie"
                :option="recLatencyPie"
                :autoresize="true"
                style="height: 260px"
              />
              <Empty v-else :description="$t('dns.page.dashboard.noData')" />
            </Card>
          </Col>
        </Row>

        <!-- ===== Authoritative ===== -->
        <h3 style="margin: 16px 0 12px 0">{{ $t('dns.page.dashboard.authoritative') }}</h3>

        <Row :gutter="16" style="margin-bottom: 16px">
          <Col :span="8">
            <Card>
              <Statistic
                :title="$t('dns.page.dashboard.authBackendQps')"
                :value="formatRate(snapshot.authBackendQps)"
              />
            </Card>
          </Col>
          <Col :span="8">
            <Card>
              <Statistic
                :title="$t('dns.page.dashboard.authPacketCache')"
                :value="formatPct(snapshot.authPacketCacheRatio)"
                :value-style="{ color: ratioColor(snapshot.authPacketCacheRatio) }"
              />
            </Card>
          </Col>
          <Col :span="8">
            <Card>
              <Statistic
                :title="$t('dns.page.dashboard.authQueryCache')"
                :value="formatPct(snapshot.authQueryCacheRatio)"
                :value-style="{ color: ratioColor(snapshot.authQueryCacheRatio) }"
              />
            </Card>
          </Col>
        </Row>

        <Row :gutter="16" style="margin-bottom: 16px">
          <Col :span="12">
            <Card :title="`${$t('dns.page.dashboard.authBackend')} (${activeWindow.label})`" size="small">
              <VChart
                v-if="authBackendChart"
                :option="authBackendChart"
                :autoresize="true"
                style="height: 260px"
              />
              <Empty v-else :description="$t('dns.page.dashboard.noData')" />
            </Card>
          </Col>
          <Col :span="12">
            <Card :title="`${$t('dns.page.dashboard.authErrors')} (${activeWindow.label})`" size="small">
              <VChart
                v-if="authErrorChart"
                :option="authErrorChart"
                :autoresize="true"
                style="height: 260px"
              />
              <Empty v-else :description="$t('dns.page.dashboard.noData')" />
            </Card>
          </Col>
        </Row>
      </Spin>
    </div>
  </Page>
</template>
