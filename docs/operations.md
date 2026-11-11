# Операційний посібник

Усі команди — на Mac у папці `~/Documents/AntiFraud`, якщо не сказано інше.

## Перше налаштування

| Крок | Команда |
|---|---|
| 1. Вхід по SSH-ключу (один раз) | `bash ssh-setup.sh` → далі `ssh phish-vps` без пароля |
| 2. Розгортання сервісу | `bash deploy.sh` → `deploy.log`, `result-vps.json`, `shot-vps.jpg` |
| 3. Увімкнути LLM | `bash set-llm-key.sh` (ключ з `phish-render/api-key` або спитає) |
| 4. Підключити Telegram-бота для моніторингу | `bash monitor.sh telegram` |

## Щоденні команди

| Задача | Команда |
|---|---|
| Аудит бренду, чекати результат | `bash run-audit.sh <бренд> <офіційний.домен> [ще.домен]` |
| Кілька аудитів у черзі | `bash run-audit.sh --no-wait <бренд> <домен>` (повторити для кожного) |
| Забрати готові аудити | `bash run-audit.sh fetch` |
| Додаткові домени в аудит | `EXTRA="домен1 домен2" bash run-audit.sh ...` |
| Прогін моніторингу зараз | `bash monitor.sh run [бренд]` |
| Увімкнути / вимкнути щоденний моніторинг | `bash monitor.sh on [бренд]` / `bash monitor.sh off [бренд]` |
| Стан моніторингу | `bash monitor.sh status [бренд]` |
| Оцінка точності | `bash run-eval.sh` → `eval-results-<дата>/report.md` |
| Тестовий набір через `/render` | `bash run-tests.sh` → `render-results-<дата>/` |

## Оновлення коду сервісу

`deploy.sh` заливає готовий `phish-render.tar.gz`, тож архів спершу треба перезібрати:

```bash
COPYFILE_DISABLE=1 tar czf phish-render.tar.gz \
  --exclude='.env' --exclude='api-key' --exclude='.DS_Store' --exclude='__pycache__' \
  --exclude='bin' --exclude='obj' --exclude='render_out' --exclude='result.json' --exclude='shot.jpg' \
  --exclude='monitor/telegram.env' --exclude='monitor/state' --exclude='monitor/runs' \
  phish-render
tar tzf phish-render.tar.gz | grep -E 'api-key|\.env|telegram' && echo "СТОП: секрет в архіві"
bash deploy.sh
```

`setup.sh` на сервері не перезаписує `.env`, перезбирає образ і перезапускає контейнер. Скрипти аудиту й моніторингу оновлюються самі: `run-audit.sh` і `monitor.sh` заливають свіжі `brand_audit.py` / `monitor.py` перед кожним запуском.

## На сервері

```bash
ssh phish-vps
cd ~/phish-render
```

| Задача | Команда |
|---|---|
| Чи живий сервіс | `curl -s 127.0.0.1:8080/health` |
| Логи сервісу | `docker compose logs -f render` |
| Перезапуск | `docker compose restart render` |
| Змінити налаштування | редагуй `.env`, потім `docker compose up -d` |
| Аудити, що йдуть | `ls audit_runs/`; журнал: `tail -f audit_runs/<назва>/audit.log` |
| Таймери моніторингу | `systemctl list-timers 'phish-monitor@*'` |
| Журнал моніторингу | `journalctl -u phish-monitor@kachorovska -n 100` |
| Ізоляція мережі | `systemctl status render-egress`, `iptables -S DOCKER-USER` |
| Доступ до API з Mac | `ssh -L 8080:127.0.0.1:8080 phish-vps`, далі `http://localhost:8080` |

## Налаштування `.env`

| Змінна | За замовчуванням | Що робить |
|---|---|---|
| `RENDER_API_KEY` | генерує `setup.sh` | Ключ для `/render` і `/check`, ≥24 символи |
| `MAX_CONCURRENCY` | 2 | Паралельні рендери (≈1 на 1,5 ГБ RAM) |
| `NAV_TIMEOUT_MS` | 20000 | Таймаут завантаження сторінки |
| `HARD_TIMEOUT_MS` | 60000 | Жорстка межа на весь рендер |
| `QUEUE_TIMEOUT_MS` | 30000 | Скільки чекати вільного слота до 503 |
| `SETTLE_MS` | 4000 | Скільки чекати, поки мережа сторінки затихне (JS-редиректи, догрузка форм) |
| `MAX_REQUESTS_PER_PAGE` | 400 | Ліміт запитів сторінки |
| `ANTHROPIC_API_KEY` | — | Ключ Claude; без нього лише правила |
| `LLM_MODEL` | `claude-haiku-5-5` | Модель судді |
| `LLM_DAILY_LIMIT` | 300 | Викликів LLM на добу |
| `RENDER_MEM_LIMIT` | 2g | Ліміт пам'яті контейнера (docker compose) |
| `BROWSER_CHANNEL` | — | `default`, якщо Chromium не стартує з помилкою про channel |

## Секрети

| Секрет | Де | Як замінити |
|---|---|---|
| Ключ сервісу | `.env` на сервері | Нове значення `RENDER_API_KEY`, потім `docker compose up -d` |
| Ключ Claude API | `.env` на сервері, `phish-render/api-key` на Mac | Новий ключ у консолі Claude → `bash set-llm-key.sh` → відкликати старий |
| Токен Telegram-бота | `monitor/telegram.env` на сервері, `tg-bot-api` на Mac | @BotFather `/revoke` → `bash monitor.sh telegram` |

Секрети не потрапляють в архів (`.gitignore`, `.dockerignore`, `--exclude` вище). Перед відправкою архіву чи папки комусь — перевір.

## Усунення несправностей

| Симптом | Причина й що робити |
|---|---|
| `ssh: connect ... Network is unreachable` / timeout | Немає інтернету або сервер лежить. Перевір панель uavps.net; `ping 91.228.218.128` |
| SSH питає пароль | Ключ не налаштовано на цьому Mac: `bash ssh-setup.sh` |
| `/health` → `browser_down` | `docker compose restart render`; якщо повторюється — `docker compose logs --tail 100 render` |
| HTTP 503 `busy` | Усі слоти зайняті (часто паралельний аудит). Дочекайся або збільш `MAX_CONCURRENCY` (і RAM) |
| HTTP 401 | Неправильний `X-Api-Key`; інструменти беруть ключ з `~/phish-render/.env` |
| У `reasons` «LLM недоступна» | Ключ, баланс або ліміт API; або вичерпано `LLM_DAILY_LIMIT` (див. `/health`) |
| Аудит «у черзі» довго | Попередній аудит ще йде (`flock`). Дивись `audit_runs/<назва>/audit.log` активного |
| Аудит завис на «Журнал SSL-сертифікатів (crt.sh)» | Для великих брендів crt.sh відповідає хвилинами; якщо понад 15 хв — crt.sh перевантажений, перезапусти пізніше |
| Зведення моніторингу без кількості імен із журналу сертифікатів | crt.sh не відповів або відповів неповно; аудит пройшов на варіантах назви, події «новий сертифікат» цього дня не рахуються |
| Багато `dns_failed` у тестах | Нормально: фішингові домени живуть днями. Бери свіжі адреси (`fetch_feed.py`) |
| Таймер не спрацював | `systemctl list-timers`; таймер міг бути вимкнений (`monitor.sh status`) |

## Резервні копії

Зараз немає. Що варто копіювати (раз на тиждень, на Mac):

```bash
ssh phish-vps 'tar czf - -C ~/phish-render monitor/state monitor/*.json' > backup-monitor-$(date +%Y%m%d).tar.gz
```

Код на Mac не під git — див. ризики в [architecture.md](architecture.md), §9.
