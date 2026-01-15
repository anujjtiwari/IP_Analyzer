## Delete the backend
To Delete the backend, if the backend is running then stop the backend and then execute following commands:
```
pipenv --rm
rm -f Pipfile
rm -f Pipfile.lock
```

## Delete the frontend
Stop the frontend if it is running.
Delete the frontend folder
```
rm -rf frontend
```