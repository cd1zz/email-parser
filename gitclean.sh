# --- existing steps ---
git branch backup-main
git checkout --orphan temp-main
git add -A
git commit -m "Initial clean commit"
git branch -D main
git branch -m main

# --- NEW: delete local side branches ---
for br in $(git for-each-ref --format='%(refname:short)' refs/heads/ | grep -v '^main$'); do
    git branch -D "$br"
done

# --- NEW: delete remote side branches (push deletes) ---
for br in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin/ | grep -v '^main$'); do
    git push origin --delete "${br#origin/}"
done

# --- final push with clean history & only main ---
git push --force --set-upstream origin main
