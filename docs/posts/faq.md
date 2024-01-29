---
title: FAQ 
description: Frequently asked questions for sish 
keywords: [sish, faq]
---

# Where can I find latest releases?

Builds are made automatically for each commit to the repo and are pushed to
Dockerhub. Builds are tagged using a commit sha, branch name, tag, `latest` if
released on `main`.

- [Image Registry](https://hub.docker.com/r/antoniomika/sish/tags)
- [OS/arch binaries](https://github.com/antoniomika/sish/releases)

# How does sish compare to ngrok?

The goals are similar, but the underlying tech is different. With `sish` the
end-user doesn't need to install any cli tool in order to use it. We are simply
leveraging SSH to make the connections that the `ngrok` cli would use.

# Who can I contact with questions?

If you have any questions or comments, feel free to reach out via email
[me@antoniomika.me](mailto:me@antoniomika.me) or on libera IRC
[#sish](https://web.libera.chat/#sish)
