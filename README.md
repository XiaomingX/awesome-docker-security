# awesome-docker-security（Docker 安全资源大全）

这里收集了关于 Docker 安全的优秀资源，包括书籍、博客、视频、工具以及案例。

## 书籍

- [Liz Rice 著《容器安全》](https://learning.oreilly.com/library/view/container-security/9781492056690/)
- [Adrian Mouat 著《Docker 安全》](https://learning.oreilly.com/library/view/docker-security/9781492042297/)
- [Chiheb Chebbi 著《高级基础设施渗透测试》](https://learning.oreilly.com/library/view/advanced-infrastructure-penetration/9781788624480/)

## 博客

- [Docker 安全](https://docs.docker.com/engine/security/)
- [OWASP Docker 安全](https://github.com/OWASP/Docker-Security)
- [容器安全简介：理解 Docker 的隔离特性](https://www.docker.com/sites/default/files/WP_IntrotoContainerSecurity_08.19.2016.pdf)
- [一次攻击分析：Docker 仓库](https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/)
- [寻找不安全的 Docker 仓库](https://medium.com/@act1on3/hunting-for-insecure-docker-registries-d87d293e6779)
- [如何利用 Docker API 进行远程代码执行](https://www.blackhat.com/docs/us-17/thursday/us-17-Cherny-Well-That-Escalated-Quickly-How-Abusing-The-Docker-API-Led-To-Remote-Code-Execution-Same-Origin-Bypass-And-Persistence_wp.pdf)
- [在 CI 或测试环境中使用 Docker-in-Docker？请三思](https://jpetazzo.github.io/2015/09/03/do-not-use-docker-in-docker-for-ci/)
- [Docker 容器环境中的漏洞利用](https://www.blackhat.com/docs/eu-15/materials/eu-15-Bettini-Vulnerability-Exploitation-In-Docker-Container-Environments-wp.pdf)
- [缓解 RunC 高严重性漏洞 (CVE-2019-5736)](https://blog.aquasec.com/runc-vulnerability-cve-2019-5736)
- [构建安全的 Docker 镜像 - 101](https://medium.com/walmartlabs/building-secure-docker-images-101-3769b760ebfa)
- [使用 OPA Rego 规则和 Conftest 进行 Dockerfile 安全检查](https://blog.madhuakula.com/dockerfile-security-checks-using-opa-rego-policies-with-conftest-32ab2316172f)
- [攻击者如何看待 Docker：解析多容器应用程序](https://i.blackhat.com/us-18/Thu-August-9/us-18-McGrew-An-Attacker-Looks-At-Docker-Approaching-Multi-Container-Applications-wp.pdf)
- [第四课：像大佬一样入侵容器](https://www.practical-devsecops.com/lesson-4-hacking-containers-like-a-boss/)
- [如何通过 Containerd 加密来保护 Docker 镜像](https://www.whitesourcesoftware.com/free-developer-tools/blog/secure-docker-with-containerd/)

## 视频

- [构建安全 Docker 镜像的最佳实践](https://www.youtube.com/watch?v=LmUw2H6JgJo)
- [OWASP Bay Area - 使用开源工具攻击和审计 Docker 容器](https://www.youtube.com/watch?v=ru7GicI5iyI)
- [DockerCon 2018 - Docker 容器安全](https://www.youtube.com/watch?v=E_0vxpL_lxM)
- [DockerCon 2019 - Netflix 容器安全的理论与实践](https://www.youtube.com/watch?v=bWXne3jRTf0)
- [DockerCon 2019 - 使用 Rootless 模式加强 Docker 守护进程](https://www.youtube.com/watch?v=Qq78zfXUq18)
- [RSAConference 2019 - 我如何从经验中学习 Docker 安全（所以你不必经历）](https://www.youtube.com/watch?v=C343TPOpTzU)
- [BSidesSF 2020 - 检查你的 --privileged 容器](https://www.youtube.com/watch?v=5VgSFRyI38w)
- [实时容器攻击：夺旗比赛 - Andrew Martin (Control Plane) 对阵 Ben Hall (Katacoda)](https://www.youtube.com/watch?v=iWkiQk8Kdk8)

## 工具

### 容器运行时

- [gVisor](https://github.com/google/gvisor) - 用 Go 编写的应用内核，实现在 Linux 系统上运行的大部分功能。
- [Kata Container](https://github.com/kata-containers/kata-containers) - 一个开源项目，致力于构建轻量级虚拟机（VM），这些虚拟机的体验和性能像容器，但提供了类似 VM 的隔离和安全优势。
- [sysbox](https://github.com/nestybox/sysbox) - 一个开源容器运行时，使 Docker 容器能够作为虚拟服务器运行 Systemd、Docker、Kubernetes 等软件。
- [Firecracker](https://github.com/firecracker-microvm/firecracker-containerd) - 专为创建和管理安全多租户容器和基于函数的服务而开发的虚拟化技术。

### 容器扫描

- [trivy](https://github.com/aquasecurity/trivy) - 适用于 CI 的简单且全面的容器漏洞扫描工具。
- [Clair](https://github.com/quay/clair) - 静态漏洞分析工具，发现容器中的 CVE，可集成到 CI，如 Gitlab CI。
- [Harbor](https://github.com/goharbor/harbor) - 开源的云原生注册表项目，具备 RESTful API、注册表、漏洞扫描和 RBAC 等功能。
- [Anchore Engine](https://anchore.com) - 容器镜像检查、分析和认证的集中服务，支持 RESTful API 和 Anchore CLI。
- [grype](https://github.com/anchore/grype) - Anchore 的开源漏洞扫描工具，可对容器镜像和文件系统进行扫描。
- [Dagda](https://github.com/eliasgranderubio/dagda/) - 静态分析工具，检测 Docker 镜像和容器中的已知漏洞、木马、病毒、恶意软件等威胁。
- [Synk](https://snyk.io) - 用于发现和修复开源依赖中的已知漏洞，支持容器扫描和应用安全。

### 合规检查

- [Docker 安全基准](https://github.com/docker/docker-bench-security) - 脚本，检查生产环境中部署 Docker 容器的多项最佳实践。
- [CIS Docker 基准 - InSpec profile](https://github.com/dev-sec/cis-docker-benchmark) - 以自动化方式实现 CIS Docker 1.13.0 基准，提供生产环境中的 Docker 守护进程和容器的安全最佳实践测试。
- [lynis](https://github.com/CISOfy/Lynis) - Linux、macOS、UNIX 系统的安全审计工具，协助合规测试和系统加固，免安装。
- [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) - 开源通用策略引擎，用于整个技术栈的统一、上下文感知的策略执行。
- [opa-docker-authz](https://github.com/open-policy-agent/opa-docker-authz) - Docker 的策略授权插件。

### 渗透测试

- [BOtB](https://github.com/brompwnie/botb) - 容器分析与利用工具，适合渗透测试人员和 CI/CD 环境。
- [Gorsair](https://github.com/Ullaakut/Gorsair) - Docker API 渗透测试工具，用于发现和远程访问 Docker 容器。
- [Cloud Container Attack Tool](https://github.com/RhinoSecurityLabs/ccat) - 测试容器环境安全的工具。
- [DEEPCE](https://github.com/stealthcopter/deepce) - Docker 枚举、权限提升和容器逃逸工具。

### 测试环境

- [DockerSecurityPlayground (DSP)](https://github.com/giper45/DockerSecurityPlayground) - 基于微服务的框架，用于研究网络安全和渗透测试技术。
- [Katacoda 课程：Docker 安全](https://www.katacoda.com/courses/docker-security) - 通过交互式场景学习 Docker 安全。
- [Control Plane 提供的 Docker 安全课程](https://control-plane.io/training) - Control Plane 提供的 Docker 安全课程。
- [Play with Docker](https://labs.play-with-docker.com/) - 学习 Docker 的简单、交互式、免费的在线环境。
- [OWASP WrongSecrets](https://github.com/commjoen/wrongsecrets) - 漏洞应用程序，涵盖秘密管理中的不良做法，包括 Docker。

### 监控

- [Falco](https://github.com/falcosecurity/falco) - 云原生运行时安全工具。
- [Wazuh](https://wazuh.com) - 免费开源的企业级安全监控解决方案，用于威胁检测、完整性监控、事件响应和合规。
- [Weave Scope](https://www.weave.works/oss/scope/) - 自动检测进程、容器、主机，无需内核模块或代理，适用于 Docker、Kubernetes、AWS ECS 等环境。

### 其他工具

- [anchor](https://github.com/SongStitch/anchor/) - 确保 Dockerfile 中的依赖项可重复构建。
- [dive](https://github.com/wagoodman/dive) - 探索 Docker 镜像中每一层的工具。
- [hadolint](https://github.com/hadolint/hadolint) - Dockerfile 代码规范检查工具，帮助构建最佳实践的 Docker 镜像。
- [dockle](https://github.com/goodwithtech/dockle) - 容器镜像的代码规范检查工具。
- [docker_auth](https://github.com/cesanta/docker_auth) - Docker 注册表的认证服务器。
- [bane](https://github.com/genuinetools/bane) - Docker 容器的自定义 AppArmor 配置生成器。
- [secret-diver](https://github.com/cider-rnd/secret-diver) - 分析容器中的敏感信息。
- [confine](https://github.com/shamedgh/confine) - 为 Docker 镜像生成 SECCOMP 配置文件。
- [imgcrypt](https://github.com/containerd/imgcrypt) - OCI 镜像加密包。
- [lazydocker](https://github.com/jesseduffield/lazydocker) - 简化 Docker 镜像和容器管理的工具。

## 案例

- [如何破解 Play-with-Docker 并远程在主机上运行代码](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)
- [黑客组织利用公开的 Docker API 接口劫持系统](https://www.zdnet.com/article/a-hacking-group-is-hijacking-docker-systems-with-exposed-api-endpoints/)
- [数百个漏洞 Docker 主机被加密货币矿工利用](https://www.imperva.com/blog/hundreds-of-vulnerable-docker-hosts-exploited-by-cryptocurrency-miners/)
- [加密劫持蠕虫攻击了超过 2000 个 Docker 主机](https://www.helpnetsecurity.com/2019/10/18/cryptojacking-worm-docker/)
- [Docker API 漏洞让黑客挖取门罗币](https://www.scmagazineuk.com/docker-api-vulnerability-allows-hackers-mine-monero/article/1578021)
- [Docker 注册表 HTTP API v2 未加密暴露，导致镜像泄露与污染](https://hackerone.com/reports/347296)
- [如何通过请求拆分漏洞找到 Portainer 的 RCE 并黑进 Uber](https://medium.com/@andrewaeva_55205/how-dangerous-is-request-splitting-a-vulnerability-in-golang-or-how-we-found-the-rce-in-portainer-7339ba24c871)
- [Docker 注册表暴露导致数百家企业面临恶意软件和数据盗窃风险](https://threatpost.com/docker-registries-malware-data-theft/152734/)
- [Doki 后门入侵云中的 Docker 服务器](https://threatpost.com/doki-backdoor-docker-servers-cloud/157871/)
- [威胁者通过容器逃逸功能攻击 Docker](https://www.trendmicro.com/en_us/research/21/b/threat-actors-now-target-docker-via-container-escape-features.html)
- [CVE-2020-15157：Containerd 漏洞可能导致云凭据泄露](https://blog.aquasec.com/cve-2020-15157-containerd-container-vulnerability)
