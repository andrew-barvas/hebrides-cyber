// Values for monitored_targets.criticality / .environment (migration 067).
// Kept apart from estatePriority.ts so browser code (MonitoredTargets.tsx)
// can import them without pulling in the server-side loaders.
export const CRITICALITIES = ["low", "normal", "high"] as const;
export type Criticality = (typeof CRITICALITIES)[number];

export const ENVIRONMENTS = ["production", "staging", "development", "test"] as const;
export type Environment = (typeof ENVIRONMENTS)[number];
