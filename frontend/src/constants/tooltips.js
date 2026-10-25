export const TOOLTIPS = {
  LOLBin: {
    term: "LOLBin",
    definition: "Living-off-the-Land Binary — công cụ có sẵn của Windows (MSBuild, certutil, rundll32) bị malware lợi dụng để thực thi code độc hại mà không cần tải file lạ."
  },
  MSBuild: {
    term: "MSBuild",
    definition: "Công cụ build của Microsoft. Hacker lợi dụng để chạy C# code ẩn trong file .csproj, không tải binary độc hại về máy."
  },
  "T1127.001": {
    term: "T1127.001 - MSBuild",
    definition: "MITRE ATT&CK technique: kẻ tấn công lợi dụng MSBuild để thực thi payload trong quá trình build, tránh antivirus."
  },
  "T1059": {
    term: "T1059 - Command Execution",
    definition: "MITRE ATT&CK technique: sử dụng command-line interpreter (cmd, powershell, bash) để thực thi lệnh độc hại."
  },
  "T1071": {
    term: "T1071 - Application Layer Protocol",
    definition: "MITRE ATT&CK technique: malware giao tiếp với C2 server qua protocol ứng dụng (HTTP, DNS) để tránh bị phát hiện."
  },
  C2: {
    term: "C2 - Command & Control",
    definition: "Máy chủ điều khiển malware từ xa. Malware gọi về C2 đều đặn để nhận lệnh và gửi dữ liệu đánh cắp."
  },
  Beaconing: {
    term: "Beaconing",
    definition: "Hành vi malware gọi về C2 server theo chu kỳ đều đặn (mỗi 15s, 30s, 60s) — khác với traffic người dùng bình thường."
  },
  Isolation: {
    term: "Network Isolation",
    definition: "Cô lập mạng: chặn tất cả traffic ra/vào, chỉ giữ kết nối tới Manager. Agent vẫn nhận lệnh nhưng không liên lạc được C2."
  },
  Quarantine: {
    term: "Quarantine",
    definition: "Cách ly: block internet nhưng cho phép SSH (port 22) và DNS (port 53) để admin truy cập từ xa điều tra."
  },
  "Reverse Shell": {
    term: "Reverse Shell",
    definition: "Kẻ tấn công mở shell trên máy nạn nhân từ xa. Máy nạn nhân chủ động kết nối về Kali của attacker để tránh firewall."
  },
  CredentialDumping: {
    term: "Credential Dumping",
    definition: "Đánh cắp mật khẩu từ memory (LSASS trên Windows) bằng mimikatz/procdump — kỹ thuật kinh điển của APT và ransomware."
  },
  EMA: {
    term: "EMA - Exponential Moving Average",
    definition: "Làm mượt điểm rủi ro theo thời gian. Điểm mới = 0.35 × raw + 0.65 × điểm cũ. Tránh đồ thị răng cưa."
  },
  HealthScore: {
    term: "Health Score",
    definition: "Điểm sức khỏe tổng quan 0-100. Tính từ: critical incidents, medium incidents, agents offline."
  },
  AutoIsolated: {
    term: "AUTO-ISOLATED",
    definition: "Cô lập mạng tự động: chặn tất cả traffic ra/vào, chỉ giữ kết nối tới Manager. Agent vẫn nhận lệnh nhưng không liên lạc được C2."
  },
  RiskScore: {
    term: "Risk Score",
    definition: "Điểm rủi ro cao nhất của agent trong 5 phút qua."
  },
  RulesTriggered: {
    term: "Detection Rules",
    definition: "Có các rule phát hiện hành vi bất thường kích hoạt trên agent."
  },
  PID: {
    term: "PID",
    definition: "Process ID - số định danh duy nhất của tiến trình trên hệ điều hành."
  },
  PPID: {
    term: "Parent PID",
    definition: "PID của process cha đã spawn ra process này."
  },
  Cmdline: {
    term: "Command Line",
    definition: "Command line - câu lệnh và tham số đầy đủ đã chạy process này."
  },
  Applied: {
    term: "Applied",
    definition: "Hành động phản ứng an ninh đã được áp dụng thành công lên agent."
  },
  Reverted: {
    term: "Reverted",
    definition: "Hành động phản ứng đã được hoàn nguyên (undo / rollback)."
  },
  Cooldown: {
    term: "Cooldown",
    definition: "Thời gian chờ chống rung giật (flapping) để tránh bật/tắt liên tục các hành động phản ứng."
  },
  StatusOpen: {
    term: "Open / Active",
    definition: "Sự cố an ninh mới phát hiện, đang chờ xử lý."
  },
  StatusInvestigating: {
    term: "Investigating",
    definition: "Analyst đang điều tra phân tích nguyên nhân gốc."
  },
  StatusContained: {
    term: "Contained",
    definition: "Mối đe dọa đã được ngăn chặn hoặc máy trạm đã được cô lập mạng."
  },
  StatusResolved: {
    term: "Resolved",
    definition: "Sự cố đã được khắc phục hoàn toàn."
  },
  StatusFalsePositive: {
    term: "False Positive",
    definition: "Cảnh báo nhầm, đã được xác nhận không phải tấn công."
  },
  StatusClosed: {
    term: "Closed",
    definition: "Sự cố đã hoàn tất và đóng hồ sơ."
  }
};
