export interface SystemStats {
    cpu_usage: number;
    memory_used: number;
    memory_total: number;
    disk_used: number;
    disk_total: number;
    timestamp: number;
}

export interface ContainerInfo {
    id: string;
    name: string;
    image: string;
    status: string;
    state: string;
    ports: string;
}

export interface SecurityEvent {
    id: number;
    event_key: string;
    event_type: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    message: string;
    evidence_json: string;
    status: "open" | "acknowledged" | "resolved";
    first_seen: number;
    last_seen: number;
    acknowledged_at?: number | null;
    resolved_at?: number | null;
}
