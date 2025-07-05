# aws-serverless-security-monitoring
This MSc Cybersecurity project showcases a serverless AWS setup for log monitoring, threat detection, and auto-remediation using Terraform (IaC). It compares manual server-based AWS via CLI vs. automated serverless architecture with integrated security and CSPM tools.

graph TD
    subgraph Log Sources
        A[EC2 Instance] -- Application/System Logs --> B(CloudWatch Agent)
        C -- API Calls --> D
        E[VPC] -- Network Traffic --> F[VPC Flow Logs]
    end

    subgraph Log Ingestion & Storage
        B -- Forward Logs --> G[CloudWatch Logs]
        D -- Forward Logs --> G
        F -- Forward Logs --> H
        H -- Optional Processing/Forwarding --> G
    end

    subgraph Monitoring & Detection
        G -- Metrics & Alarms --> I[CloudWatch Alarms & Metric Filters]
        G -- Log Analysis --> J[CloudWatch Logs Insights]
        D -- API Audit Logs --> K
        L -- Configuration Changes --> M
    end

    subgraph Aggregation & Notification
        I -- Trigger --> N
        K -- Findings --> O
        M -- Compliance Findings --> O
        O -- Alerts/Events --> N
        O -- Events --> P
    end

    subgraph Automated Remediation
        P -- Trigger --> Q
        N -- Trigger (Optional) --> Q
        Q -- Orchestrate --> R
        R -- Remediate Actions --> L
        Q -- Remediate Actions --> L
    end

    subgraph Human Intervention & Review
        N -- Notifications --> S
        J -- Manual Analysis --> S
        O -- Unified Dashboard --> S
    end

    style A fill:#f9f,stroke:#333,stroke-width:2px
    style C fill:#f9f,stroke:#333,stroke-width:2px
    style E fill:#f9f,stroke:#333,stroke-width:2px
    style B fill:#bbf,stroke:#333,stroke-width:2px
    style D fill:#bbf,stroke:#333,stroke-width:2px
    style F fill:#bbf,stroke:#333,stroke-width:2px
    style G fill:#ccf,stroke:#333,stroke-width:2px
    style H fill:#ccf,stroke:#333,stroke-width:2px
    style I fill:#9cf,stroke:#333,stroke-width:2px
    style J fill:#9cf,stroke:#333,stroke-width:2px
    style K fill:#9cf,stroke:#333,stroke-width:2px
    style M fill:#9cf,stroke:#333,stroke-width:2px
    style N fill:#ffc,stroke:#333,stroke-width:2px
    style O fill:#ffc,stroke:#333,stroke-width:2px
    style P fill:#ffc,stroke:#333,stroke-width:2px
    style Q fill:#afa,stroke:#333,stroke-width:2px
    style R fill:#afa,stroke:#333,stroke-width:2px
    style S fill:#eee,stroke:#333,stroke-width:2px

    A -- "Collects" --> B
    C -- "Logs" --> D
    E -- "Logs" --> F
    B -- "Sends" --> G
    D -- "Sends" --> G
    F -- "Sends" --> H
    H -- "For Analysis/Archival" --> G
    G -- "Monitors & Filters" --> I
    G -- "Queries" --> J
    D -- "Analyzes" --> K
    L -- "Monitors" --> M
    I -- "Sends Alerts" --> N
    K -- "Sends Findings" --> O
    M -- "Sends Findings" --> O
    O -- "Routes Findings" --> P
    N -- "Sends Notifications" --> S
    J -- "Provides Insights" --> S
    O -- "Displays Consolidated View" --> S
    P -- "Triggers" --> Q
    Q -- "Executes" --> R
    R -- "Modifies/Fixes" --> L
    Q -- "Modifies/Fixes" --> L
