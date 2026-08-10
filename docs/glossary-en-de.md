# SOC Glossary — English / Deutsch / Русский

A bilingual glossary for the SOC Triage Lab. Useful for L1 interviews
(ANOVIS — Vienna) and daily language practice.

## Architecture (die Architektur)

| EN | DE | RU |
|----|----|----|
| Hexagonal architecture | die Hexagonalarchitektur | гексагональная архитектура |
| Ports & Adapters | Ports & Adapter | порты и адаптеры |
| Core / Domain | der Kern / die Domäne | домен / ядро |
| Infrastructure / Adapters | die Infrastruktur / die Adapter | инфраструктура / адаптеры |
| Delivery / Web layer | die Bereitstellungsschicht | слой доставки |
| Port (interface) | die Schnittstelle | интерфейс (порт) |
| Entity | die Entität | сущность |
| Service (use case) | der Dienst / der Anwendungsfall | сервис (прецедент) |
| Dependency Injection | die Abhängigkeitseinspritzung | внедрение зависимостей |
| Framework-agnostic | frameworkunabhängig | независимый от фреймворка |
| Test / Unit test | der Test / der Unit-Test | тест / юнит-тест |
| Repository | das Repository | репозиторий |
| Container | der Container | контейнер |
| Docker image | das Docker-Image | образ Docker |

## Pipeline — Collect (die Erfassung)

| EN | DE | RU |
|----|----|----|
| Log event | das Logereignis | событие лога |
| Log source | die Logquelle | источник логов |
| Timestamp | der Zeitstempel | метка времени |
| Field | das Feld | поле |
| ECS (Elastic Common Schema) | das ECS-Schema | стандарт полей Elastic |
| Seed (deterministic) | der Seed (deterministisch) | зерно генерации |
| Event stream | der Ereignisstrom | поток событий |

## Pipeline — Detect (die Erkennung)

| EN | DE | RU |
|----|----|----|
| Detector | der Detektor | детектор |
| Alert | der Alarm | алерт |
| Signature | die Signatur | сигнатура |
| Pattern | das Muster | паттерн |
| Match | die Übereinstimmung | совпадение |
| Threshold | der Schwellenwert | порог |
| Sliding window | das gleitende Zeitfenster | скользящее окно |
| Brute Force | die Brute-Force-Attacke | подбор пароля |
| SQL Injection | die SQL-Injektion | SQL-инъекция |
| Cross-Site Scripting (XSS) | das Cross-Site-Scripting | межсайтовый скриптинг |
| Port Scan | der Portscan | сканирование портов |
| Phishing | das Phishing | фишинг |
| User-Agent | der User-Agent | пользовательский агент |
| Scanner / Offensive tool | der Scanner | сканер |
| False positive | der Fehlalarm | ложное срабатывание |
| False negative | die verpasste Erkennung | пропущенная атака |

## Pipeline — Triage (die Sichtung)

| EN | DE | RU |
|----|----|----|
| Severity | der Schweregrad | серьёзность |
| Critical / High / Medium / Low / Info | Kritisch / Hoch / Mittel / Niedrig / Info | критично / высокая / средняя / низкая / инфо |
| Escalate | die Eskalation | эскалация |
| Resolve | die Behebung | закрытие |
| IoC (Indicator of Compromise) | der Kompromittierungsindikator | индикатор компрометации |
| Confidence | die Konfidenz | уверенность |
| Policy | die Richtlinie | политика |
| Decision | die Entscheidung | решение |
| Priority | die Priorität | приоритет |

## Pipeline — Correlate (die Korrelation)

| EN | DE | RU |
|----|----|----|
| Correlation | die Korrelation | корреляция |
| Incident | der Sicherheitsvorfall | инцидент |
| Strategy | die Strategie | стратегия |
| Time window | das Zeitfenster | временное окно |
| Group by IoC / source / technique | gruppieren nach | группировка по |
| Campaign | die Kampagne | кампания |

## Pipeline — Respond (die Reaktion)

| EN | DE | RU |
|----|----|----|
| Playbook | das Playbook / das Handbuch | плейбук |
| Step | der Schritt | шаг |
| Action | die Maßnahme | действие |
| Mitigation | die Schadensbegrenzung | смягчение |
| Containment | die Eindämmung | сдерживание |
| Eradication | die Beseitigung | устранение |
| Recovery | die Wiederherstellung | восстановление |
| Enrichment | die Anreicherung | обогащение |
| MITRE ATT&CK | das MITRE ATT&CK | таксономия MITRE |
| Tactic | die Taktik | тактика |
| Technique | die Technik | техника |
| Guidance | die Anleitung | инструкция |

## Pipeline — Visualize & Notify (die Visualisierung und Benachrichtigung)

| EN | DE | RU |
|----|----|----|
| Dashboard | das Dashboard | дашборд |
| Report | der Bericht | отчёт |
| Renderer | der Renderer | рендерер |
| Notification | die Benachrichtigung | уведомление |
| API | die API / die Schnittstelle | API |
| Endpoint | der Endpunkt | эндпоинт |
| Health check | der Gesundheitscheck | проверка здоровья |

## SOC Fundamentals (die SOC-Grundlagen) — вакансия ANOVIS

| EN | DE | RU |
|----|----|----|
| SOC (Security Operations Center) | das Sicherheitsoperationszentrum | центр мониторинга безопасности |
| SOC Analyst L1/L2/L3 | der SOC-Analyst | аналитик 1/2/3 уровня |
| Shift / Night shift | die Schicht / die Nachtschicht | смена / ночная смена |
| Monitoring | die Überwachung / das Monitoring | мониторинг |
| Threat | die Bedrohung | угроза |
| Threat Intelligence | die Bedrohungsinformationen | разведка угроз |
| Threat Hunting | die Bedrohungssuche | охота за угрозами |
| Vulnerability | die Schwachstelle | уязвимость |
| Exploit | der Exploit | эксплойт |
| Malware | die Schadsoftware | вредоносное ПО |
| Ransomware | die Ransomware | вымогатель |
| SIEM | das SIEM | SIEM |
| SOAR | das SOAR | SOAR |
| Firewall | die Firewall | межсетевой экран |
| Endpoint | der Endpunkt | конечная точка |
| Authentication | die Authentifizierung | аутентификация |
| MFA | die Mehrfaktorauthentifizierung | многофакторная аутентификация |
| DNS / VPN / AV | das DNS / das VPN / der Virenschutz | DNS / VPN / антивирус |
| Documentation | die Dokumentation | документирование |
| Escalation to L2/L3 | die Eskalation an L2/L3 | передача на уровень 2/3 |
| Criminal record extract | der Strafregisterauszug | справка о несудимости |
| Collective agreement | der Kollektivvertrag | коллективный договор |
| Part-time / Full-time | die Teilzeit / die Vollzeit | частичная / полная занятость |
