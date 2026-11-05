# Public growth readiness — 20 October 2026

This pass prepares the organization for discovery, contribution, technical review
and future support. It preserves the [complete DICN goal](GOAL.md), original
acceptance evidence and current Storage/compute/application priorities. It does
not add product functionality or establish new runtime acceptance.

## Audit and priorities

Live read-only GitHub APIs covered **all 13 public repositories** at the start of
this pass: core; Browser, Chat, Mail, Code, Cloud, Image, Map, Weather, Bank and
Citizen; organization `.github`; and `volparossa.github.io`. Existing descriptions,
20-topic application sets and detailed READMEs were generally useful. Names were
consistent and did not justify disruptive renames. Private repository content
and authenticated traffic data are excluded from this public record.

| Priority | Finding and decision | Benefit / effort / risk / maintenance |
| --- | --- | --- |
| 1 | Existing Pages publishes `VOLPAROSSA/volparossa.github.io`, `main:/`, to `volparossa.org`, with HTTPS enforced. Its root contained only README, CNAME and license, serving a small placeholder. Build the public entry point in that repository. | High discovery benefit; bounded static implementation; low risk with original CNAME/hosting retained; no framework or service dependency. |
| 2 | Shared `.github` had contribution/security guidance but lacked conduct, support, accessibility and default forms. Extend the shared defaults, preserving core overrides. | High newcomer benefit across repositories; small documentation cost; one place to maintain. |
| 3 | Good technical evidence was buried and README trial links lagged the ledger. Add an audience-oriented overview and refresh only stale claims. | High credibility benefit; low implementation risk; link to original evidence instead of duplicating a status system. |
| 4 | Every public repository homepage was unset; profile pinned only core. Supply verified website links, repair sparse metadata and recommend focused pins. | Low effort; reversible; preserve useful existing descriptions/topics. Pin management remains a GitHub UI operation. |
| 5 | There were no actual open issues. All 28 open items were PRs, mostly substantial integration work. Add only bounded introductory tasks justified by documentation/accessibility gaps. | Useful entry points without relabeling difficult acceptance work; finite triage burden. |
| 6 | Sponsors is pending and funders have different eligibility/AI policies. Prepare factual research and private review drafts. | Useful funding readiness; no account/application/legal action; revisit terms when a real opportunity arises. |

The Pages source, custom domain and HTTPS configuration were inspected before
editing. No DNS, hosting, network or development-host configuration change is
part of this work. The existing organization artwork is retained with provenance.

## Change and verification record

- Shared community [PR10](https://github.com/VOLPAROSSA/.github/pull/10) merged at
  `aefa317543eb2e778d7657ae7395158534f927e9`: conduct, support, accessibility,
  practical contributor routes, issue/PR templates and clearer profile navigation.
  Independent review, relative-link checks, three YAML parses and diff checks
  pass. Live community profiles resolve inherited CoC/PR guidance across the organization;
  applications report 100%. A score does not prove a healthy or accessible community.
  Private vulnerability reporting was already enabled on all 13 public repositories.
- Core documentation adds [an overview with three source-bound demonstrations](../community/OVERVIEW.md),
  [support/partnership boundaries](../community/SUPPORTING.md), clearer newcomer
  instructions, central discussion links and scope-appropriate PR checks.
  Existing technical guidance, local issue forms and historical failures remain.
- Website [PR1](https://github.com/VOLPAROSSA/volparossa.github.io/pull/1) adds the
  buildless entry point at source `bf098e3`: no JavaScript, remote fonts, analytics
  or payment endpoint; canonical/social metadata, sitemap and all ten app links.
  Independent review and inert checks pass. Firefox ESR 153.5 checks pass at
  320/390/760/1024/1440 CSS pixels, with visible keyboard focus, skip-link activation
  and 200% text at 390 pixels. The asset total is 792,340 bytes, including responsive
  artwork variants. The linked PR records the subsequent Pages deployment and
  live-content verification; local checks alone do not establish publication.
- Two genuine introductory documentation tasks are open: [prerequisite output
  guidance](https://github.com/VOLPAROSSA/volparossa/issues/294) and [an accessible
  route-diagram explanation](https://github.com/VOLPAROSSA/volparossa/issues/295),
  each labelled `good first issue` and `documentation`. Both have bounded scope
  and acceptance criteria, with no network setup or mentoring promise.
- Metadata uses the existing verified `https://volparossa.org/` destination, with
  narrow corrections to the community/website descriptions and topics, and Bank's
  outdated “proposed Transaction-layer” description. Repository names and useful
  application descriptions/topics remain intact. No funding link is added.

### Original evidence checked, not rerun

GitHub run metadata confirms success for transport `34047766913` on `482e33d0`,
Android Weather `38717988016` on `aac5be7f`, and Code `38824828727` on `fd4ff968`.
The overview states their exact scope and limitations. This pass does not rerun
models, build the network or requalify newer revisions. The pre-existing main
Quality run [39470852148](https://github.com/VOLPAROSSA/volparossa/actions/runs/39470852148)
on `5df31ad2` failed one source-admission test with `Authentication` (693 passed,
1 failed in that test binary). This earlier failure is retained; no causal claim
or unrelated product correction is made by these documentation changes. Artifact availability is
not implied by a successful run badge.

## Baseline and lightweight measurement

Start-of-pass public baseline: **13 public repositories, 1 star, 0 forks,
0 organization followers, 0 actual open issues, 28 open PRs and 1 Discussion**.
GitHub's `open_issues_count` includes PRs; do not use it as an issue count.
Per-repository contributor totals are not unique humans and were not summed.
Independent contributor counts, onboarding completion and website search
visibility were not established. Authenticated traffic is short-window,
repository-local data and is retained only in the maintainer's local audit.

After a substantive milestone, spend a small, sustainable review window on:

- Independent reproductions and accepted external contributions, with their actual scope.
- Whether a newcomer completed one safe task, and where the instructions failed.
- Unanswered questions and concrete accessibility/documentation barriers.
- Original test outcomes, release-readiness gaps and funding status.

Use public aggregate API counts and voluntary feedback. Do not identify visitors,
install analytics, infer user adoption from stars or promise a response SLA.
Contributor recognition requires consent. No scheduled automation or paid service
was created. Accessibility checks in this pass are bounded, not a conformance claim.

## Growth and funding roadmap

**First month:** keep entry points and links accurate; offer two bounded tasks;
review one appropriate technical discussion draft and the current Sponsors ticket.
Choose a realistic maintainer review cadence instead of promising constant support.

**Second month:** learn from one independent onboarding or reproduction attempt;
resolve its concrete friction. Publish a development update only when there is a
substantive result and the maintainer approves the communication. Prefer an upstream
fix or useful technical question to repeating a general announcement.

**Third month:** reassess which conversations produced useful feedback, code or
research. Confirm actual costs and capacity before a funding target. Recheck
eligibility, AI rules and deadlines; focus on one appropriate route rather than
submitting many weak applications. Funding never replaces technical acceptance.

The local review packet contains a project introduction, contributor invitation,
development update, media facts, three audience-specific drafts, a 90-day outreach
plan, Sponsors tier assessment, a support-ticket follow-up and factual research on
seven funding routes. It is intentionally not committed or sent. Near-term research
favours eventual Sponsors and a conditional SIDN Pioniers assessment; NLnet's
[20 October policy](https://nlnet.nl/foundation/policies/generativeAI/2.0) conflicts
with ongoing AI-authored funded artifacts. No NLnet application text was generated.
Research partnerships and company/equity routes need further prerequisites.

## Actions still requiring a human decision or unavailable UI operation

- Approve any external announcement, community post or support follow-up before it is sent.
- Decide on actual budget and applicant details before funding applications,
  new payment accounts, legal commitments or commercial outreach. Do not restart
  the pending Sponsors application or publish an unusable funding link.
- Consider pinning core, Weather and Code, then the website and one current
  application dependency. The inspected public GraphQL schema has no repository
  pin mutation; current pinning was left intact rather than using an unsupported API.
- Set repository social-preview artwork through GitHub's supported UI if desired;
  the website's sharing image and documented source can be reused subject to its
  recorded provenance. No unsupported settings endpoint was used.
- A broader screen-reader/device audit and independent contributor trial remain
  useful follow-up work. Do not report either as completed from static checks.

## Public-facing messaging implementation — 21 October 2026

The follow-up implements visitor-facing copy in the organization profile, existing
website, core README and all ten application READMEs. Broad network aspirations
now lead into recognizable tasks: getting a forecast, working on code, keeping
files and photographs, delivering messages and examining a public proposal.
The shared core's value is explained as reusable services and a way for one
contribution to benefit several integrations. Each application has its own
reason to participate, with upstream identity and technical documentation retained.

These are arguments for the project and its development, not new capability
claims. Modest-device access and server-independent services remain aims; private
peer computation, complete storage maintenance and other unfinished work remain
explicit. Weather's stale Android wording is corrected to the existing exact-build
emulator result, with real-product expiry and physical-device support still open.
No energy, cost, coverage, privacy or adoption guarantee is introduced.

| Public entry point | Reviewable change |
| --- | --- |
| [Organization profile](https://github.com/VOLPAROSSA) | [.github PR11](https://github.com/VOLPAROSSA/.github/pull/11) |
| [Existing website](https://volparossa.org/) | [Pages-source PR2](https://github.com/VOLPAROSSA/volparossa.github.io/pull/2) |
| [Core README](../../README.md) | This repository's scoped public-messaging change |
| Browser | [PR19](https://github.com/VOLPAROSSA/volparossa-browser/pull/19) |
| Chat | [PR6](https://github.com/VOLPAROSSA/volparossa-chat/pull/6) |
| Mail | [PR5](https://github.com/VOLPAROSSA/volparossa-mail/pull/5) |
| Code | [PR21](https://github.com/VOLPAROSSA/volparossa-code/pull/21) |
| Cloud | [PR18](https://github.com/VOLPAROSSA/volparossa-cloud/pull/18) |
| Image | [PR10](https://github.com/VOLPAROSSA/volparossa-image/pull/10) |
| Map | [PR6](https://github.com/VOLPAROSSA/volparossa-map/pull/6) |
| Weather | [PR27](https://github.com/VOLPAROSSA/volparossa-weather/pull/27) |
| Bank | [PR9](https://github.com/VOLPAROSSA/volparossa-bank/pull/9) |
| Citizen | [PR4](https://github.com/VOLPAROSSA/volparossa-citizen/pull/4) |

Documentation targets/anchors and whitespace checks pass. Independent review
found no unsupported current-capability claims. The website checker and Firefox
153.5 checks pass at 320/390/760/1024/1440 CSS pixels, with loaded images, no
horizontal overflow, working keyboard skip/focus and 200% text at 390 pixels.
Artwork, CSS, hosting and DNS are unchanged. These checks cover presentation,
not full accessibility conformance or renewed runtime acceptance. The linked PRs
hold source revisions and integration status. Original successes and failures
remain attached to their historical builds.
