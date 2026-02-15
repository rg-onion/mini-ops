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
