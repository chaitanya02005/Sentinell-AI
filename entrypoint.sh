#!/bin/sh
set -e

echo "Waiting for PostgreSQL..."
python manage.py wait_for_database \
  --timeout "${DATABASE_WAIT_TIMEOUT:-60}" \
  --interval "${DATABASE_WAIT_INTERVAL:-2}"

if [ "${DJANGO_ENV:-development}" = "production" ] || [ "${VALIDATE_DEPLOYMENT:-false}" = "true" ]; then
  echo "Validating deployment environment..."
  python manage.py validate_deployment
fi

if [ "${CHECK_MIGRATIONS:-true}" = "true" ]; then
  echo "Checking for migration drift..."
  python manage.py makemigrations --check --dry-run
fi

if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
  echo "Applying database migrations..."
  python manage.py migrate --noinput
fi

if [ "${COLLECT_STATIC:-true}" = "true" ]; then
  echo "Collecting static assets..."
  python manage.py collectstatic --noinput
fi

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

exec gunicorn sentinell_ai.wsgi:application \
  --bind "0.0.0.0:${PORT:-8000}" \
  --workers "${WEB_CONCURRENCY:-3}" \
  --threads "${GUNICORN_THREADS:-2}" \
  --timeout "${GUNICORN_TIMEOUT:-120}" \
  --graceful-timeout "${GUNICORN_GRACEFUL_TIMEOUT:-30}" \
  --keep-alive "${GUNICORN_KEEP_ALIVE:-5}" \
  --access-logfile - \
  --error-logfile -
