# Update Procfile to include collectstatic
@"
web: python manage.py collectstatic --noinput && python manage.py migrate --noinput && gunicorn authproject.wsgi --log-file -
"@ | Out-File -FilePath Procfile -Encoding UTF8