# Contributing to libseccomp-rs

We're really glad you're interested in contributing to libseccomp-rs!
This document has a few pointers and guidelines to help you get started.
It is not perfect, and there will always be exceptions to the rules described
here, but by following the instructions below you should have a much easier time
getting your work merged with the upstream project.

## Questions

You can use [GitHub Discussions] to ask questions (Category Q&A).
As for issues, you should first search if your question might be already asked
(and answered).

[GitHub Discussions]: https://github.com/libseccomp-rs/libseccomp-rs/discussions

## Issues

We use [GitHub's issue tracker].

[GitHub's issue tracker]: https://github.com/libseccomp-rs/libseccomp-rs/issues

### Bug Reports

Before submitting a new bug report, please search existing issues to see if
there's something related. If not, just [open a new issue][open-bug-report]!

The more information you can give in your issue, the easier it is to figure out
how to fix it. For libseccomp-rs, this will likely include the [upstream libseccomp]
version, the Linux kernel version, the architecture, the Rust version, and the
libseccomp-rs version. In addition, it is incredibly helpful if you can
describe/include a minimal reproducer for the problem in the description as well as
instructions on how to test for the bug.

[open-bug-report]: https://github.com/libseccomp-rs/libseccomp-rs/issues/new?assignees=&labels=bug&template=bug_report.md&title=
[upstream libseccomp]: https://github.com/seccomp/libseccomp

### Feature / API Requests

If you'd like a new API or feature added, please [open a new issue][open-feature-request]
requesting it. As with reporting a bug, the more information you can provide,
the better.

[open-feature-request]: https://github.com/libseccomp-rs/libseccomp-rs/issues/new?assignees=&labels=enhancement&template=feature_request.md&title=

## Pull Requests

GitHub pull requests are the primary mechanism we use to change libseccomp-rs.
Please submit Pull Requests by following [GitHub's documentation].

Even tiny pull requests (e.g. one character pull request fixing a typo in API
documentation) are greatly appreciated. Before making a large change, it is
usually a good idea to first open an issue describing the change to solicit
feedback and guidance. This will increase the likelihood of the PR getting merged.

If you change the API by way of adding, changing or removing something or if you
fix a bug, please add an appropriate note to the [change log]. We follow the
conventions of [Keep A CHANGELOG].

[change log]: https://github.com/libseccomp-rs/libseccomp-rs/blob/main/CHANGELOG.md
[GitHub's documentation]: https://help.github.com/articles/using-pull-requests/
[Keep A CHANGELOG]: https://keepachangelog.com/en/1.0.0/

### Writing Documentation

Good documentation is really important because it can help users understand
what an item is, how it is used, and for what purpose it exists.

We have our own format for documentation based on the
[Documentation of Rust API Guidelines].
This leads to more readable and understandable documentation.
If you add a new API, you should write the documentation by following our format.

```rust
/// Summary of the function on one line. (Start from "verb-s")
///
/// Detailed description of the function. (If you have)
///
/// Description of the return value on success.
/// (Start from "This function returns...")
///
/// Link to the documentation of the underlying upstream libseccomp function.
///
/// # Arguments (If the function has arguments)
///
/// * `arg` - Description of the argument
///
/// # Errors (If the function returns `Result`)
///
///  If this function encounters..., an error will be returned.
///
/// # Panics (If the function can `panic`)
///
/// Panics if...
///
/// # Examples (If you want to show the example)
///
/// ```
/// Example codes
/// ```
pub fn foo() {
```

[Documentation of Rust API Guidelines]: https://rust-lang.github.io/api-guidelines/documentation.html

### Testing Your Code

Any submissions which add functionality, or significantly change the existing
code, you should include additional tests to verify the proper operation of the
proposed changes and ensure that libseccomp-rs does not regress in the future.

In addition, we encourage you to check that the test suite passes locally before
submitting a pull request with your changes. If anything does not pass, typically
it will be easier to iterate and fix it locally than waiting for the CI servers
to run tests for you.

libseccomp-rs has a number of tests. You can run the standard regression tests
and static checks as follows:

```bash
$ make check
```

In order to use it, the `rustfmt` and `clippy` are needed, which can be installed
as follows:

```bash
$ rustup component add rustfmt clippy
```

## Signing Your Work

The sign-off is a simple line at the end of the explanation for the
patch, which certifies that you wrote it or otherwise have the right to
pass it on as an open-source patch. The rules are pretty simple: if you
can certify the below (from [developercertificate.org]):

[developercertificate.org]: http://developercertificate.org/

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
660 York Street, Suite 102,
San Francisco, CA 94110 USA

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

then you just add a line to every git commit message:

    Signed-off-by: Random J Developer <random@developer.example.org>

You can add the sign off when creating the git commit via `git commit -s`.
