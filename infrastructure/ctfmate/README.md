# CTFmate

CTFmate is a CTF collaboration tool.

Its purpose is to allow you to collaborate with your teammates even if you are not next to each other.

The tool uses Firebase, and is pre-configured to run on a demo firebase account, which you can see [here](https://ctfmate.com).

# Deployment

To deploy your own:

1.  [Create a database](https://firebase.google.com/docs/database/web/start)
1.  Update index.html with your own configuration from the step above
1.  Configure the database security rules as database.json
1.  [Enable GitHub login](https://firebase.google.com/docs/auth/web/github-auth)
1.  [Enable Firebase storage](https://firebase.google.com/docs/storage/web/start)
1.  Configure the storage security rules as storage.rules

Note: This is not an officialy supported Google product.
