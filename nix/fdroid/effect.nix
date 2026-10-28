# Publishes the signed APK as an F-Droid repo on gh-pages and as the
# `nightly` release asset. Runs as a nixbot effect on main with the
# `fdroid` secret: apk_keystore/repo_keystore (base64 PKCS12) + password.
{
  mkEffect,
  lib,
  tincr-app,
  fdroidserver,
  apksigner,
  git,
  gh,
  jdk17_headless,
  rev,
}:
mkEffect {
  name = "fdroid";
  checkout = true;
  secretsMap.fdroid = "fdroid";
  inputs = [
    fdroidserver
    apksigner
    git
    gh
    jdk17_headless
  ];
  effectScript = ''
    set -euo pipefail
    secret() { jq -er ".fdroid.data.$1" "$HERCULES_CI_SECRETS_JSON"; }
    secret apk_keystore | base64 -d > /build/apk.p12
    secret repo_keystore | base64 -d > /build/repo.p12
    export KS_PASS=$(secret password) JAVA_HOME=${jdk17_headless.home}

    apk=tincr-${toString tincr-app.versionCode}.apk
    apksigner sign --ks /build/apk.p12 --ks-pass env:KS_PASS \
      --out "/build/$apk" ${tincr-app}/tincr-release-unsigned.apk

    # Token for gh comes from the pushable origin nixbot set up.
    export GH_TOKEN=$(git remote get-url origin | sed -E 's#https://[^:]+:([^@]+)@.*#\1#')
    export GH_REPO=$(git remote get-url origin | sed -E 's#.*github.com/([^/]+/[^/.]+).*#\1#')
    gh release view nightly >/dev/null 2>&1 ||
      gh release create nightly --prerelease --title nightly --notes "Latest build of main. F-Droid repo: see README."
    cp "/build/$apk" /build/tincr.apk
    gh release upload nightly /build/tincr.apk --clobber

    # gh-pages is rebuilt as an orphan commit each time. Only the last few
    # APKs are carried over so the branch stays small.
    if git fetch origin gh-pages 2>/dev/null; then
      git worktree add /build/old FETCH_HEAD
    fi
    git worktree add --orphan -b pages /build/pages
    cd /build/pages
    mkdir -p repo metadata
    ls -t /build/old/repo/*.apk 2>/dev/null | head -n 2 | xargs -r cp -t repo/
    cp "/build/$apk" repo/
    cp ${./io.thalheim.tincr.yml} metadata/io.thalheim.tincr.yml
    cat > config.yml <<EOF
    repo_url: https://$(echo "$GH_REPO" | cut -d/ -f1 | tr A-Z a-z).github.io/$(echo "$GH_REPO" | cut -d/ -f2)/repo
    repo_name: tincr
    repo_description: Builds of tincr from main.
    repo_keyalias: repo
    keystore: /build/repo.p12
    keystorepass: $KS_PASS
    keypass: $KS_PASS
    keydname: CN=tincr
    apksigner: $(command -v apksigner)
    EOF
    chmod 600 config.yml
    fdroid update
    rm config.yml
    touch .nojekyll
    git add -A
    git -c user.name=nixbot -c user.email=nixbot@thalheim.io commit -qm "fdroid: ${rev}"
    git push -f origin pages:gh-pages
  '';
}
