#!/usr/bin/env python3
"""Offline ledger and decision checks. Never sends, browses, uploads or spends.

Records are agent-entered observations, not independent proof of user consent or
remote delivery. The agent must corroborate them using trusted conversation and
actual tool results. Python 3.10+, standard library only.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import stat
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit, unquote

ROOT = Path(__file__).resolve().parents[1]
DEFAULTS = json.loads((ROOT / 'config/defaults.json').read_text())
REGISTRY = json.loads((ROOT / 'config/sources.json').read_text())
SOURCES = {s['id']: s for s in REGISTRY['sources']}
EXCLUSIONS = json.loads((ROOT / 'config/exclusions.json').read_text())
LEDGER_LOCK_TIMEOUT_SECONDS = 1.0


class WorkflowError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise WorkflowError(message)


def finite_number(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        # Unsupported numeric magnitude must fail closed, not escape as a traceback.
        return False


def text_value(value):
    return isinstance(value, str) and bool(value.strip())


def text_list(value, label, allow_empty=True):
    require(isinstance(value, list) and (allow_empty or bool(value))
            and all(text_value(item) for item in value), label + ' must be a list of nonblank strings')


def validate_state(state):
    """Reject unknown formats without claiming a tamper-proof ledger.

    Profile replacement remains available to repair a previously entered profile;
    individual commands validate the contents they use before making a transition.
    """
    require(isinstance(state, dict), 'ledger must be a JSON object')
    require(type(state.get('schema_version')) is int and state['schema_version'] == 1,
            'unsupported ledger schema; preserve the file and review migration before continuing')
    require(isinstance(state.get('profile'), dict), 'ledger profile must be an object')
    require(isinstance(state.get('records'), dict), 'ledger records must be an object')
    require(isinstance(state.get('source_checks'), list)
            and all(isinstance(item, dict) for item in state['source_checks']),
            'ledger source checks must be a list of objects')
    require(state.get('standing_scope') is None or isinstance(state['standing_scope'], dict),
            'ledger standing scope must be an object or null')
    current = state.get('standing_scope')
    if current:
        validate_scope(current)
        require(current['kind'] == 'standing', 'active scope must be standing')
        instant(current.get('granted_at'))
    grants = state.get('standing_scope_grants')
    if grants is not None:
        require(isinstance(grants, dict), 'standing scope grants must be an object')
        for reference, scope in grants.items():
            validate_scope(scope)
            require(text_value(reference) and scope['kind'] == 'standing'
                    and reference == scope['user_instruction_ref'], 'invalid standing scope grant identity')
            instant(scope.get('granted_at'))
        current = state.get('standing_scope')
        if current:
            reference = current.get('user_instruction_ref')
            require(reference in grants and current == grants[reference]
                    and not current.get('revoked'), 'active standing scope disagrees with retained grant history')
    for key, record in state['records'].items():
        require(text_value(key) and isinstance(record, dict), 'ledger job records must be objects with text keys')
        require(isinstance(record.get('job'), dict), 'ledger job must be an object')
        require(record.get('stage') in ('evaluated', 'prepared', 'submitted', 'responded'), 'invalid ledger stage')
        for field in ('history', 'receipts'):
            require(isinstance(record.get(field), list)
                    and all(isinstance(item, dict) for item in record[field]),
                    'ledger ' + field + ' must be a list of objects')
        for field in ('packet', 'approval', 'execution', 'attempt_snapshot', 'block'):
            require(field not in record or isinstance(record[field], dict), 'ledger ' + field + ' must be an object')
        if 'submission_uncertain' in record:
            require(type(record['submission_uncertain']) is bool, 'submission uncertainty must be a boolean')
        if 'packet' in record:
            require(type(record['packet'].get('reviewed')) is bool, 'packet review state must be a boolean')
            if record['packet']['reviewed']:
                require(text_value(record['packet'].get('review_instruction_ref')),
                        'reviewed packet needs a nonblank instruction reference')
        attempts = [h for h in record['history'] if h.get('kind') == 'submission_attempt']
        has_attempt = 'attempt_snapshot' in record or bool(attempts) or 'attempt_action' in record
        if has_attempt:
            snapshot = record.get('attempt_snapshot')
            require(snapshot and len(attempts) == 1 and attempts[0].get('detail') == snapshot
                    and attempts[0].get('at') == snapshot.get('at'),
                    'inconsistent attempt evidence; preserve ledger and reconcile before continuing')
            require(snapshot.get('job_key') == key and record.get('attempt_action') == snapshot.get('action')
                    and snapshot.get('action') in ('application_submit', 'application_email'),
                    'inconsistent attempt identity or action')
            require(record['stage'] in ('prepared', 'submitted', 'responded')
                    and record.get('submission_uncertain') is (record['stage'] == 'prepared'),
                    'attempt uncertainty disagrees with submission stage; preserve ledger for review')
            confirmations = [r for r in record['receipts'] if r.get('kind') in ('portal_confirmation', 'email_sent')]
            require(len(confirmations) == (0 if record['stage'] == 'prepared' else 1),
                    'submission stage disagrees with retained receipt evidence')
            instant(snapshot.get('at'))
            for receipt in confirmations:
                expected_kind = 'email_sent' if snapshot['action'] == 'application_email' else 'portal_confirmation'
                require(receipt.get('kind') == expected_kind and receipt.get('job_key') == key
                        and receipt.get('packet_sha256') == snapshot.get('packet_sha256')
                        and receipt.get('destination') == snapshot.get('destination'),
                        'saved receipt disagrees with immutable attempt target or content')
                require(all(text_value(receipt.get(field)) for field in ('external_id', 'evidence_ref', 'observed_at'))
                        and instant(receipt['observed_at']) >= instant(snapshot['at']),
                        'saved receipt evidence or time is invalid')
                require(receipt.get('attachment_sha256s', []) == snapshot.get('execution', {}).get('attachment_sha256s', []),
                        'saved receipt attachment trace mismatch')
                if expected_kind == 'email_sent':
                    require(receipt.get('recipient') == snapshot.get('recipient'), 'saved sent recipient mismatch')
        else:
            require(record['stage'] in ('evaluated', 'prepared') and not record['receipts']
                    and not record.get('submission_uncertain'), 'submission state is missing attempt evidence')
    return state


def stamp():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def instant(value):
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(dt.tzinfo is not None, 'timestamp requires timezone')
        return dt
    except (AttributeError, TypeError, ValueError) as exc:
        raise WorkflowError('invalid timestamp') from exc


def fresh(value, now, seconds):
    if not value:
        return False
    elapsed = (instant(now) - instant(value)).total_seconds()
    return 0 <= elapsed <= seconds


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode()).hexdigest()


def norm(value):
    return ' '.join(str(value).casefold().split())


def token(value):
    return re.sub(r'[^a-z0-9]', '', norm(value))


def canonical_url(value):
    require(text_value(value), 'job URL must be a nonblank string')
    u = urlsplit(value)
    require(u.scheme in ('https', 'http') and u.hostname and not u.username and not u.password,
            'job URL must be HTTP(S), without credentials')
    # Preserve identity parameters (gh_jid, jid, jobId, etc.). Never discard all query data.
    pairs = [(k, v) for k, v in parse_qsl(u.query, keep_blank_values=True)
             if not k.lower().startswith('utm_') and k.lower() not in ('gclid', 'fbclid')]
    host = u.hostname.lower()
    if u.port and u.port not in (80, 443):
        host += ':' + str(u.port)
    return urlunsplit((u.scheme.lower(), host, u.path.rstrip('/') or '/', urlencode(sorted(pairs)), ''))


def excluded(job):
    if job.get('employer_category') == 'prop_firm':
        return 'employer classified as prop firm'
    company = token(job.get('company', ''))
    if company in {token(x) for x in EXCLUSIONS['exact_company_aliases']}:
        return 'excluded company alias'
    # Check employer/dedicated ATS route identity, not arbitrary text mentioning a company.
    route = ' '.join(unquote(str(job.get(k, ''))) for k in ('url', 'application_url', 'employer_url', 'board_id'))
    compact = token(route)
    if any(x in compact for x in EXCLUSIONS['distinctive_route_tokens']):
        return 'excluded employer or board route'
    return None


def validate_profile(profile):
    require(isinstance(profile, dict), 'profile must be a JSON object')
    required = ('location', 'remote', 'relocation', 'roles', 'industries', 'pay_floor',
                'availability', 'resume_status', 'evidence', 'sources', 'assistance_level')
    missing = [k for k in required if k not in profile or profile[k] is None]
    require(not missing, 'onboarding missing: ' + ', '.join(missing))
    for field in ('location', 'remote', 'relocation', 'availability'):
        require(text_value(profile[field]), field + ' must be a nonblank answer; record unknown explicitly if needed')
    text_list(profile['roles'], 'role targets', allow_empty=False)
    text_list(profile['industries'], 'industries')
    require(profile['assistance_level'] in ('research_only', 'prepare_only'),
            'invalid assistance level')
    require(profile['resume_status'] in ('provided', 'text_provided', 'not_yet_available'), 'invalid resume status')
    floor = profile['pay_floor']
    require(isinstance(floor, dict), 'pay floor must be an object')
    require(all(k in floor for k in ('amount', 'currency', 'period', 'kind')), 'pay floor needs amount/currency/period/kind')
    require(finite_number(floor['amount']) and floor['amount'] >= 0,
            'invalid pay floor')
    require(floor['kind'] in ('base', 'contract'), 'pay floor is base or contract; OTE is not base')
    require(floor['period'] in ('year', 'month', 'week', 'hour', 'project'), 'invalid pay period')
    require(isinstance(floor['currency'], str) and re.fullmatch(r'[A-Z]{3}', floor['currency']),
            'pay floor currency needs a three-letter uppercase code')
    text_list(profile['sources'], 'sources', allow_empty=False)
    require(set(profile['sources']) <= set(SOURCES), 'unknown source')
    require(isinstance(profile['evidence'], list), 'evidence must be a list')
    seen = set()
    for item in profile['evidence']:
        require(isinstance(item, dict), 'each evidence item must be an object')
        require(all(text_value(item.get(k)) for k in ('id', 'claim', 'source')), 'evidence needs nonblank id/claim/source')
        require(item['id'] not in seen, 'duplicate evidence id')
        seen.add(item['id'])
        require(type(item.get('verified')) is bool, 'evidence needs verified boolean')
        require(type(item.get('ai_assisted')) is bool, 'evidence needs AI attribution flag')
        if item['ai_assisted']:
            require(text_value(item.get('attribution')), 'AI-assisted evidence needs exact contribution attribution')
    # Do not require citizenship, protected traits or identity documents during setup.
    return profile


def evidence_map(profile):
    return {x['id']: x for x in profile['evidence']}


def pay_assessment(profile, job):
    p, f = job.get('compensation', {}), profile['pay_floor']
    require(isinstance(p, dict), 'compensation must be an object')
    if not p.get('source_ref') or any(p.get(k) != f[k] for k in ('currency', 'period', 'kind')):
        return 'unknown_or_not_comparable'
    lo, hi = p.get('min'), p.get('max')
    if any(not finite_number(v) for v in (lo, hi)) or lo > hi:
        return 'unknown_or_not_comparable'
    if hi < f['amount']:
        return 'below_floor'
    if lo < f['amount']:
        return 'overlaps_floor'
    return 'meets_floor'


def assess(profile, job, now):
    validate_profile(profile)
    require(isinstance(job, dict), 'posting must be a JSON object')
    require(all(text_value(job.get(k)) for k in ('company', 'title', 'url', 'source_id')), 'job identity needs nonblank text')
    canonical_url(job['url'])
    require(job['source_id'] in SOURCES, 'unknown source')
    require(job['source_id'] in profile['sources'], 'source is outside configured search')
    reasons, gaps, demonstrated = [], [], []
    ex = excluded(job)
    if ex:
        reasons.append(ex)
    if job.get('employer_category') != 'non_prop' or not job.get('classification_evidence'):
        reasons.append('employer classification unverified')
    v = job.get('verification', {})
    require(isinstance(v, dict), 'verification must be an object')
    if 'application_active' in v:
        require(type(v['application_active']) is bool, 'application_active must be a boolean')
    if v.get('status') != 'active' or not v.get('evidence_ref'):
        reasons.append('posting or application not verified active')
    if not fresh(v.get('checked_at'), now, DEFAULTS['posting_fresh_hours'] * 3600):
        reasons.append('posting stale or check time invalid')
    if not job.get('application_url') or v.get('application_active') is not True:
        reasons.append('active application missing')
    else:
        canonical_url(job['application_url'])
    pay = pay_assessment(profile, job)
    if pay != 'meets_floor':
        reasons.append('pay: ' + pay)
    if norm(job.get('target_role', '')) not in {norm(r) for r in profile['roles']}:
        reasons.append('role outside targets')
    if profile['industries'] and norm(job.get('industry', '')) not in {norm(r) for r in profile['industries']}:
        reasons.append('industry outside targets')
    fit_checks = job.get('fit_checks', {})
    require(isinstance(fit_checks, dict), 'fit checks must be an object')
    for key in ('location', 'availability', 'eligibility'):
        result = fit_checks.get(key, {})
        require(isinstance(result, dict), 'each fit check must be an object')
        if result.get('status') != 'pass' or not result.get('evidence_ref'):
            reasons.append(key + ' fit unverified or incompatible')
    text_list(job.get('unknown_attestations', []), 'unknown attestations')
    if job.get('unknown_attestations'):
        reasons.append('personal attestations unanswered')
    requirements = job.get('requirements', [])
    require(isinstance(requirements, list), 'requirements must be a list')
    if not requirements:
        reasons.append('requirements not assessed')
    evidence = evidence_map(profile)
    for req in requirements:
        require(isinstance(req, dict), 'each requirement must be an object')
        require(text_value(req.get('text')), 'requirement text missing')
        ids = req.get('evidence_ids', [])
        text_list(ids, 'requirement evidence ids')
        if (req.get('assessment') == 'demonstrated' and ids and
            all(i in evidence and evidence[i]['verified'] for i in ids) and req.get('rationale')):
            demonstrated.append(req['text'])
        else:
            gaps.append({'requirement': req['text'], 'assessment': req.get('assessment', 'unknown'),
                         'reason': req.get('rationale', 'No demonstrated evidence supplied')})
    if gaps:
        reasons.append('requirements have explicit evidence gaps')
    return {'decision': 'excluded' if ex else ('review_needed' if reasons else 'ready_to_prepare'),
            'reasons': reasons, 'pay': pay, 'demonstrated': demonstrated, 'gaps': gaps,
            'assessed_at': now}


def job_key(job):
    return digest([norm(job['company']), norm(job['title']), canonical_url(job['url'])])[:20]


def duplicate(records, job):
    exact = job_key(job)
    for key, record in records.items():
        prior = record['job']
        if key == exact or canonical_url(job['url']) == canonical_url(prior['url']):
            return key, 'exact_identity_or_url'
        if (norm(job['company']) == norm(prior['company']) and job.get('ats_id') and
            job.get('ats_id') == prior.get('ats_id') and job['source_id'] == prior['source_id']):
            return key, 'same_employer_ats_id'
        if norm(job['company']) == norm(prior['company']) and norm(job['title']) == norm(prior['title']):
            return key, 'same_company_title_review'
    return None, None


def content_signature(job):
    data = copy.deepcopy(job)
    data.pop('verification', None)  # A new check is permitted; content changes require a new packet.
    return digest(data)


def event(record, kind, now, detail):
    record['history'].append({'kind': kind, 'at': now, 'detail': detail})


def initial_state(profile, now):
    validate_profile(profile)
    return {'schema_version': 1, 'created_at': now, 'profile': profile,
            'records': {}, 'source_checks': [], 'standing_scope': None, 'standing_scope_grants': {}}


def packet_hash(packet):
    return digest({'text': packet['text'], 'materials': packet['materials'],
                   'attachments': packet.get('attachments', [])})


def attachment_snapshot(item):
    path = Path(item['path']).expanduser().resolve(strict=True)
    require(path.is_file() and path.stat().st_size <= 25 * 1024 * 1024, 'attachment must be a file under 25 MiB')
    require(item.get('name') == path.name and path.suffix.lower() in ('.pdf', '.docx', '.txt'),
            'attachment filename must match a supported resume/document file')
    require(item.get('media_type') and item.get('truth_review_ref') and item.get('evidence_ids'),
            'attachment needs type and truthful content review')
    return dict(item, path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=path.stat().st_size)


def prepare_packet(profile, record, selected_ids, now, materials=None, attachments=None):
    job = record['job']
    require(not excluded(job), 'excluded employer cannot receive a packet')
    require(profile['assistance_level'] != 'research_only', 'research-only scope cannot prepare materials')
    assessment = assess(profile, job, now)
    require(assessment['decision'] != 'excluded', 'excluded job')
    verification = job.get('verification', {})
    require(verification.get('status') == 'active' and verification.get('application_active') is True
            and verification.get('evidence_ref') and job.get('application_url')
            and fresh(verification.get('checked_at'), now, DEFAULTS['posting_fresh_hours'] * 3600),
            'verify current posting and active application before preparing a targeted packet')
    ev = evidence_map(profile)
    text_list(selected_ids, 'selected evidence ids', allow_empty=False)
    require(len(selected_ids) == len(set(selected_ids)), 'select unique evidence ids')
    claims = []
    for key in selected_ids:
        require(key in ev and ev[key]['verified'], 'unverified or missing evidence: ' + key)
        claims.append(copy.deepcopy(ev[key]))
    lines = [f"Application preparation: {job['title']} at {job['company']}",
             f"Posting: {job['url']}", f"Destination: {job['application_url']}", '',
             'Resume / application claim text (review exact wording):']
    if job.get('application_route') == 'email':
        lines.insert(3, 'Published recipient: ' + str(job.get('published_recipient', 'UNVERIFIED')))
    for item in claims:
        lines.append('- ' + item['claim'])
        if item['ai_assisted']:
            lines.append('  AI-assisted work attribution: ' + item['attribution'])
    lines += ['', 'Internal review notes — do not paste into employer form:',
              'Compensation: ' + json.dumps(job.get('compensation', {}), sort_keys=True),
              'Evidence sources: ' + '; '.join(x['id'] + ': ' + x['source'] for x in claims),
              'Gaps / unresolved checks: ' + ('; '.join(assessment['reasons']) or 'None recorded'),
              'Submission status: PREPARED ONLY; no external action performed.']
    text = '\n'.join(lines) + '\n'
    if materials is None:
        materials = [{'name': 'resume-claims.txt', 'kind': 'resume_text',
                      'content': '\n'.join(x['claim'] + ('\nAI-assisted work: ' + x['attribution'] if x['ai_assisted'] else '') for x in claims) + '\n',
                      'evidence_ids': selected_ids, 'truth_review_ref': 'verbatim verified evidence'}]
    require(isinstance(materials, list) and materials, 'materials required')
    names = set()
    for material in materials:
        require(isinstance(material, dict), 'each material must be an object')
        require(text_value(material.get('name')) and material['name'] not in names, 'unique material names required')
        names.add(material['name'])
        require(text_value(material.get('content')) and text_value(material.get('truth_review_ref')),
                'materials need content and evidence review reference')
        require(material.get('kind') in ('resume_text', 'cover_letter', 'application_answers', 'email_body'), 'unsupported material kind')
        text_list(material.get('evidence_ids'), 'material evidence ids', allow_empty=False)
        require(set(material['evidence_ids']) <= set(selected_ids), 'material claims need selected evidence')
    attached = []
    require(attachments is None or isinstance(attachments, list), 'attachments must be a list')
    for item in attachments or []:
        require(isinstance(item, dict), 'each attachment must be an object')
        text_list(item.get('evidence_ids'), 'attachment evidence ids', allow_empty=False)
        require(set(item.get('evidence_ids', [])) <= set(selected_ids), 'attachment claims need selected evidence')
        require(item.get('name') not in names, 'unique material and attachment names required')
        names.add(item.get('name'))
        attached.append(attachment_snapshot(item))
    packet = {'text': text, 'materials': copy.deepcopy(materials), 'attachments': attached,
            'claim_ids': selected_ids, 'claims': claims, 'job_signature': content_signature(job),
            'profile_signature': digest(profile), 'prepared_at': now, 'reviewed': False}
    packet['sha256'] = packet_hash(packet)
    return packet


def validate_scope(scope):
    """Require typed, bounded permission records, including previously saved ones."""
    require(isinstance(scope, dict), 'approval scope must be an object')
    require(scope.get('kind') in ('exact', 'standing'), 'invalid approval scope kind')
    require(type(scope.get('revoked', False)) is bool, 'scope revoked must be a boolean')
    require(text_value(scope.get('user_instruction_ref')), 'scope must cite actual user instruction')
    text_list(scope.get('actions'), 'scope actions', allow_empty=False)
    require(set(scope['actions']) <= {'application_submit', 'application_email'}, 'invalid scope actions')
    instant(scope.get('expires_at'))
    if scope['kind'] == 'standing':
        for field in ('companies', 'roles', 'sources'):
            text_list(scope.get(field), 'scope ' + field, allow_empty=False)
        require(set(scope['sources']) <= set(SOURCES), 'unknown scope source')
        require(type(scope.get('max_actions')) is int and scope['max_actions'] > 0,
                'positive scope quota required')
    else:
        for field in ('job_key', 'packet_sha256', 'destination'):
            require(text_value(scope.get(field)), 'exact scope needs ' + field)
    return scope


def authorized(scope, job, packet, action, now):
    if not scope:
        return False
    validate_scope(scope)
    if scope.get('revoked'):
        return False
    if instant(scope.get('expires_at', '')) <= instant(now):
        return False
    if action not in scope.get('actions', []):
        return False
    if scope.get('kind') == 'exact':
        return (scope.get('job_key') == job_key(job) and scope.get('packet_sha256') == packet['sha256']
                and scope.get('destination') == job['application_url'])
    if scope.get('kind') == 'standing':
        # Explicit bounded company/role/source scope plus a per-period quota.
        return (norm(job['company']) in {norm(x) for x in scope.get('companies', [])}
                and norm(job['target_role']) in {norm(x) for x in scope.get('roles', [])}
                and job['source_id'] in scope.get('sources', [])
                and type(scope.get('max_actions')) is int and scope['max_actions'] > 0)
    return False


def gate(state, record, action, now, platform_approved=False, tool_confirmation_required=False,
         tool_confirmed=False):
    for label, value in (('platform_approved', platform_approved),
                         ('tool_confirmation_required', tool_confirmation_required), ('tool_confirmed', tool_confirmed)):
        require(type(value) is bool, label + ' must be a boolean')
    reasons = ['preparation-only pilot does not permit external application actions']
    job, profile = record['job'], state['profile']
    if action not in ('application_submit', 'application_email'):
        return {'ready': False, 'reasons': ['separate user handling or explicit action-specific confirmation required']}
    if profile['assistance_level'] != 'assisted_apply':
        reasons.append('assistance level does not permit applications')
    packet = record.get('packet')
    if not packet or not packet.get('reviewed'):
        reasons.append('exact packet has not been reviewed')
    elif (packet['job_signature'] != content_signature(job) or packet['profile_signature'] != digest(profile)
          or packet['sha256'] != packet_hash(packet)):
        reasons.append('reviewed packet or underlying inputs changed')
    if packet:
        for item in packet.get('attachments', []):
            try:
                current = attachment_snapshot(item)
                if current['sha256'] != item['sha256'] or current['bytes'] != item['bytes']:
                    reasons.append('reviewed attachment bytes changed')
            except (OSError, WorkflowError):
                reasons.append('reviewed attachment unavailable')
    assessment = assess(profile, job, now)
    reasons.extend(assessment['reasons'])
    if not fresh(job.get('verification', {}).get('checked_at'), now, DEFAULTS['submission_fresh_minutes'] * 60):
        reasons.append('recheck posting and application immediately before action')
    if record['stage'] in ('submitted', 'responded') or record.get('submission_uncertain'):
        reasons.append('existing or uncertain submission; reconcile receipts before any retry')
    if record.get('block'):
        reasons.append('technical block requires documented resolution')
    route = job.get('application_route')
    if route == 'upwork' or job['source_id'] == 'upwork':
        reasons.append('Upwork uses its own explicit preview/confirmation flow; this gate cannot authorize it')
    if route == 'indeed' or 'indeed.' in (urlsplit(job.get('application_url', '')).hostname or ''):
        reasons.append('Indeed application requires user handoff')
    if action == 'application_email':
        if route != 'email' or not job.get('published_recipient') or not job.get('recipient_evidence'):
            reasons.append('employer-published recipient unverified')
    elif route != 'portal':
        reasons.append('portal action requires portal route')
    approvals = [record.get('approval'), state.get('standing_scope')]
    valid = [s for s in approvals if packet and authorized(s, job, packet, action, now)]
    if not valid:
        reasons.append('no valid user application scope')
    elif all(s.get('kind') == 'standing' for s in valid):
        s = valid[0]
        since = instant(s['granted_at'])
        used = sum(1 for r in state['records'].values() for h in r['history']
                   if h['kind'] == 'submission_attempt' and instant(h['at']) >= since)
        if used >= s['max_actions']:
            reasons.append('standing scope action limit reached')
    if not platform_approved:
        reasons.append('platform permission check is pending')
    if tool_confirmation_required and not tool_confirmed:
        reasons.append('required tool confirmation pending')
    return {'ready': not reasons, 'reasons': list(dict.fromkeys(reasons)),
            'meaning': 'local checks only; not independent consent or a remote action'}


def validate_execution(record, data, now):
    """Bind observed host capabilities and filled contents before final action.

    These references are supplied by the agent after actual tool observations;
    JSON alone never proves a tool exists or grants consent.
    """
    packet, job = record['packet'], record['job']
    require(data.get('packet_sha256') == packet['sha256'] and data.get('destination') == job['application_url'],
            'execution target/content mismatch')
    require(all(text_value(data.get(field)) for field in ('tool_ref', 'capability_evidence_ref', 'field_evidence_ref')),
            'execution needs observed tool capability and filled-field evidence')
    mode = data.get('mode')
    require(mode in ('browser_upload', 'resume_text', 'email_attachment', 'connector'), 'unsupported execution mode')
    hashes = [a['sha256'] for a in packet.get('attachments', [])]
    if mode in ('browser_upload', 'email_attachment'):
        require(hashes and data.get('attachment_sha256s') == hashes and text_value(data.get('attachment_evidence_ref')),
                'verify exact reviewed attachments in the form/draft')
    elif mode == 'resume_text':
        require(not data.get('attachment_evidence_ref'), 'resume text route must not claim a file upload')
        require(data.get('employer_offers_text') is True and text_value(data.get('text_offer_evidence_ref')),
                'resume text alternative must be offered by this employer')
        material = next((m for m in packet['materials'] if m['name'] == data.get('material_name') and m['kind'] == 'resume_text'), None)
        require(material and data.get('text_sha256') == hashlib.sha256(material['content'].encode()).hexdigest(),
                'pasted resume must match exact approved text')
        require(not data.get('attachment_sha256s'), 'text route did not upload attachments')
    else:
        require(text_value(data.get('action_schema_ref')) and data.get('attachment_sha256s', []) == hashes,
                'connector action and exact attachments must be supported')
    if job.get('application_route') == 'email':
        require(hashes, 'email application route requires the reviewed resume attachment')
        require(mode in ('email_attachment', 'connector') and data.get('recipient') == job.get('published_recipient'),
                'email execution needs exact published recipient and supported attachment route')
        require(data.get('subject') and any(m['kind'] == 'email_body' for m in packet['materials']),
                'email execution needs reviewed body and subject')
        require(any(m['kind'] == 'application_answers' and m['content'] == data['subject'] for m in packet['materials']),
                'email subject must be frozen in reviewed materials')
    else:
        require(mode != 'email_attachment', 'email route cannot submit a portal')
    return dict(copy.deepcopy(data), checked_at=now)


def recovery(kind, attempts, elapsed, text_supported=False):
    require(type(attempts) is int and attempts >= 0 and finite_number(elapsed) and elapsed >= 0, 'invalid retry counters')
    require(type(text_supported) is bool, 'text_supported must be a boolean')
    if kind in ('captcha', 'auth', 'permission', 'prohibited', 'payment', 'attestation', 'submission_unknown'):
        return 'handoff_no_retry'
    if kind == 'upload':
        if attempts >= 1:
            return 'use_exact_reviewed_text' if text_supported else 'handoff_no_retry'
        return 'one_bounded_picker_attempt'
    if elapsed >= DEFAULTS['source_budget_seconds'] or attempts >= DEFAULTS['read_attempts_per_source']:
        return 'handoff_no_retry'
    return 'bounded_read_retry'


def record_receipt(record, receipt, now):
    kind = receipt.get('kind')
    require(kind in ('portal_confirmation', 'email_sent', 'delivery_confirmation', 'bounce', 'employer_response'),
            'receipt kind is not verified outcome evidence')
    require(receipt.get('job_key') == job_key(record['job']), 'receipt job mismatch')
    require(all(text_value(receipt.get(field)) for field in ('evidence_ref', 'external_id', 'observed_at')),
            'receipt needs evidence reference, external id and observation time')
    attempt = record.get('attempt_snapshot')
    require(attempt, 'receipt needs immutable authorized attempt snapshot')
    require(instant(attempt['at']) <= instant(receipt['observed_at']) <= instant(now),
            'receipt must be observed after the authorized attempt and not in the future')
    packet = record.get('packet', {})
    require(packet and receipt.get('packet_sha256') == packet['sha256'], 'receipt content mismatch')
    require(packet_hash(packet) == packet['sha256'], 'packet bytes changed after review or attempt')
    require(receipt.get('packet_sha256') == attempt['packet_sha256'], 'receipt attempted content mismatch')
    require(receipt.get('destination') == attempt['destination'], 'receipt destination mismatch')
    prior = record.setdefault('receipts', [])
    require(not any(r['external_id'] == receipt['external_id'] and r['kind'] == kind for r in prior), 'duplicate receipt')
    if kind in ('portal_confirmation', 'email_sent'):
        require(record['stage'] == 'prepared' and packet.get('reviewed'), 'submission receipt needs reviewed packet')
        require(record.get('submission_uncertain'), 'record authorized action attempt before receipt')
        expected = 'application_email' if kind == 'email_sent' else 'application_submit'
        require(record.get('attempt_action') == expected, 'receipt route does not match recorded action')
        require(receipt.get('attachment_sha256s', []) == attempt['execution'].get('attachment_sha256s', []),
                'receipt attachment trace mismatch')
        if 'resume_text_sha256' in receipt and attempt['execution'].get('mode') == 'resume_text':
            require(receipt['resume_text_sha256'] == attempt['execution']['text_sha256'],
                    'receipt contradicts reviewed resume text')
        if kind == 'email_sent':
            require(receipt.get('recipient') == attempt.get('recipient'), 'sent recipient mismatch')
        record['stage'] = 'submitted'
        record['submission_uncertain'] = False
        record['outcome'] = 'sent_delivery_unverified' if kind == 'email_sent' else 'application_receipt_verified'
        record['delivery_status'] = 'unverified' if kind == 'email_sent' else 'not_applicable'
    elif kind in ('bounce', 'delivery_confirmation'):
        sent = next((r for r in prior if r['kind'] == 'email_sent' and
                     r['external_id'] == receipt.get('related_message_id')), None)
        require(sent is not None, 'bounce/delivery must correlate with an exact sent message id')
        require(instant(receipt['observed_at']) >= instant(sent['observed_at']), 'delivery evidence predates sent message')
        if kind == 'delivery_confirmation':
            require(not any(r['kind'] == 'bounce' and r.get('related_message_id') == receipt.get('related_message_id') for r in prior),
                    'conflicting bounce and delivery evidence requires user review')
        record['outcome'] = 'bounced' if kind == 'bounce' else 'delivery_evidence_verified'
        record['delivery_status'] = 'bounced' if kind == 'bounce' else 'evidence_verified'
    else:
        require(record['stage'] in ('submitted', 'responded'), 'response needs submission history')
        record['stage'] = 'responded'
        record['outcome'] = receipt.get('response_outcome', 'response_received')
        record['response_outcome'] = record['outcome']
    prior.append(copy.deepcopy(receipt))
    event(record, kind, now, receipt)
    return {'stage': record['stage'], 'outcome': record['outcome']}


PILOT_COMMANDS = frozenset(('init', 'profile', 'source-check', 'evaluate', 'recheck',
    'prepare', 'review', 'gate', 'block', 'resolve-block', 'show'))


def reduce(state, command, data, now):
    """One atomic local transition. Mutates a loaded in-memory state only."""
    require(command in PILOT_COMMANDS, 'command disabled in preparation-only pilot')
    instant(now)
    require(isinstance(data, dict), 'input must be a JSON object')
    if command == 'init':
        require(state is None, 'state already exists; refusing to overwrite')
        return initial_state(data, now), {'status': 'onboarded', 'external_actions': 0}
    require(state is not None, 'initialize a profile first')
    validate_state(state)
    if command == 'profile':
        state['profile'] = validate_profile(data)
        return state, {'status': 'updated; existing packet reviews invalidated by input signature'}
    if command == 'source-check':
        require(data.get('source_id') in SOURCES, 'unknown source')
        require(data.get('status') in ('active', 'blocked', 'stale', 'unverified', 'closed', 'requires_connection'), 'invalid source state')
        require(data.get('method') and data.get('evidence_ref'), 'source check needs method and evidence reference')
        state['source_checks'].append(dict(data, checked_at=now))
        return state, state['source_checks'][-1]
    if command == 'standing-scope':
        require(type(data.get('revoked', False)) is bool, 'scope revoked must be a boolean')
        grants = state.setdefault('standing_scope_grants', {})
        current = state.get('standing_scope')
        # Retain the known active grant when loading an older compatible ledger.
        if current and current['user_instruction_ref'] not in grants:
            grants[current['user_instruction_ref']] = copy.deepcopy(current)
        if data.get('revoked'):
            if current:
                grants[current['user_instruction_ref']]['revoked'] = True
            state['standing_scope'] = None
            return state, {'status': 'revoked; original grant retained to prevent replay'}
        validate_scope(data)
        require(data['kind'] == 'standing', 'standing scope required')
        require(instant(data['expires_at']) > instant(now), 'scope expired')
        reference = data['user_instruction_ref']
        if reference in grants:
            prior = grants[reference]
            require(not prior.get('revoked') and current and current.get('user_instruction_ref') == reference,
                    'instruction was revoked or superseded; a new actual user instruction is required')
            terms = lambda scope: {k: v for k, v in scope.items() if k not in ('granted_at', 'revoked')}
            require(terms(data) == terms(prior), 'same instruction cannot change standing scope terms')
            state['standing_scope'] = copy.deepcopy(prior)
            return state, {'status': 'scope already recorded; original grant time and quota retained'}
        if current:
            grants[current['user_instruction_ref']]['revoked'] = True
        state['standing_scope'] = dict(data, granted_at=now, revoked=False)
        grants[reference] = copy.deepcopy(state['standing_scope'])
        return state, {'status': 'scope recorded; corroborate against trusted conversation before use'}
    if command == 'evaluate':
        assessment = assess(state['profile'], data, now)
        key, reason = duplicate(state['records'], data)
        if key:
            return state, {'duplicate': key, 'reason': reason, 'prior_stage': state['records'][key]['stage'],
                           'prior_outcome': state['records'][key].get('outcome'), 'assessment': assessment}
        key = job_key(data)
        record = {'job': copy.deepcopy(data), 'stage': 'evaluated', 'assessment': assessment,
                  'history': [], 'receipts': [], 'outcome': None}
        event(record, 'evaluated', now, assessment)
        state['records'][key] = record
        return state, {'job_key': key, 'stage': 'evaluated', 'assessment': assessment}
    key = data.get('job_key')
    require(key in state['records'], 'unknown job key')
    record = state['records'][key]
    if command == 'recheck':
        job = data['job']
        require(job_key(job) == key, 'recheck identity differs; review duplicate identity first')
        record['assessment'] = assess(state['profile'], job, now)
        record['job'] = copy.deepcopy(job)
        event(record, 'rechecked', now, {'job': job, 'assessment': record['assessment']})
        return state, record['assessment']
    if command == 'prepare':
        require(record['stage'] in ('evaluated', 'prepared') and not record.get('submission_uncertain'), 'cannot replace attempted/submitted packet')
        record['packet'] = prepare_packet(state['profile'], record, data['evidence_ids'], now, data.get('materials'), data.get('attachments'))
        record.pop('approval', None)
        record.pop('execution', None)
        record['stage'] = 'prepared'
        event(record, 'prepared', now, {'packet': copy.deepcopy(record['packet'])})
        return state, record['packet']
    if command == 'review':
        packet = record.get('packet')
        require(packet and data.get('packet_sha256') == packet['sha256'] and text_value(data.get('user_instruction_ref')), 'review must identify exact packet and nonblank user instruction reference')
        packet['reviewed'] = True
        packet['review_instruction_ref'] = data['user_instruction_ref']
        event(record, 'reviewed', now, data)
        return state, {'reviewed': True, 'stage': record['stage'],
                       'submitted': None if record.get('submission_uncertain') else record['stage'] in ('submitted', 'responded'),
                       'submission_uncertain': record.get('submission_uncertain', False), 'external_actions': 0}
    if command == 'approval':
        validate_scope(data)
        require(data['kind'] == 'exact', 'exact approval required')
        require(record.get('packet') and data.get('packet_sha256') == record['packet']['sha256'], 'approval hash mismatch')
        require(data.get('destination') == record['job']['application_url'], 'approval destination mismatch')
        require(instant(data['expires_at']) > instant(now), 'approval expired')
        record['approval'] = copy.deepcopy(data)
        event(record, 'approval_recorded', now, data)
        return state, {'status': 'recorded; platform and tool approvals still required'}
    if command == 'execution':
        require(not record.get('submission_uncertain') and record['stage'] == 'prepared', 'cannot replace attempted execution')
        record['execution'] = validate_execution(record, data, now)
        event(record, 'execution_observed', now, record['execution'])
        return state, record['execution']
    if command in ('gate', 'attempt'):
        result = gate(state, record, data['action'], now, data.get('platform_approved', False),
                      data.get('tool_confirmation_required', False), data.get('tool_confirmed', False))
        if command == 'attempt':
            require(result['ready'], '; '.join(result['reasons']))
            execution = record.get('execution')
            require(execution and fresh(execution['checked_at'], now, DEFAULTS['submission_fresh_minutes'] * 60),
                    'observe current execution capability and filled content before attempt')
            validate_execution(record, execution, now)
            record['submission_uncertain'] = True
            record['attempt_action'] = data['action']
            record['attempt_snapshot'] = {'at': now, 'action': data['action'], 'job_key': key,
                'packet_sha256': record['packet']['sha256'], 'destination': record['job']['application_url'],
                'recipient': record['job'].get('published_recipient'), 'execution': copy.deepcopy(execution)}
            event(record, 'submission_attempt', now, copy.deepcopy(record['attempt_snapshot']))
        return state, result
    if command == 'receipt':
        return state, record_receipt(record, data, now)
    if command == 'bounce-check':
        require(data.get('evidence_ref') and data.get('related_message_id'), 'bounce check needs search evidence and sent id')
        require(any(r['kind'] == 'email_sent' and r['external_id'] == data['related_message_id'] for r in record['receipts']), 'sent id unknown')
        require(data.get('result') == 'none_found', 'use receipt command to record a correlated bounce')
        record['bounce_check'] = dict(data, checked_at=now)
        event(record, 'bounce_check', now, record['bounce_check'])
        return state, {'outcome': record['outcome'], 'note': 'no bounce found is not delivery proof'}
    if command == 'block':
        result = recovery(data['kind'], data.get('attempts', 0), data.get('elapsed_seconds', 0), data.get('text_supported', False))
        record['block'] = dict(data, next_action=result, recorded_at=now)
        event(record, 'blocked', now, record['block'])
        return state, record['block']
    if command == 'resolve-block':
        require(data.get('evidence_ref') and data.get('resolution'), 'resolution requires observed evidence')
        require(not record.get('submission_uncertain'), 'reconcile uncertain submission through receipt; never auto-clear it')
        record.pop('block', None)
        event(record, 'block_resolved', now, data)
        return state, {'status': 'resolved'}
    raise WorkflowError('unknown command')


def atomic_write(path, state):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix='.job-search-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(state, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def acquire_ledger_lock(handle):
    """Wait at most one second; never delete or steal another process's lock."""
    import fcntl
    deadline = time.monotonic() + LEDGER_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError as exc:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WorkflowError('ledger busy; another command holds its lock. Wait for that command to finish, then retry; do not remove the lock.') from exc
            time.sleep(min(0.05, remaining))


def read_json_file(path):
    """Refuse special files without blocking on a FIFO before inspecting its type."""
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, 'r', encoding='utf-8') as handle:
        require(stat.S_ISREG(os.fstat(handle.fileno()).st_mode), 'JSON input must be a regular file')
        return json.load(handle)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('init', 'profile', 'source-check', 'evaluate', 'recheck', 'prepare',
        'review', 'approval', 'standing-scope', 'gate', 'execution', 'attempt', 'receipt', 'bounce-check', 'block', 'resolve-block', 'show'))
    parser.add_argument('--state', type=Path, required=True, help='Explicit private ledger path outside installed skill')
    parser.add_argument('--input', type=Path, help='JSON document; no network actions are performed')
    args = parser.parse_args()
    try:
        require(args.command in PILOT_COMMANDS, 'command disabled in preparation-only pilot')
        path = args.state.resolve()
        require(not path.is_relative_to(ROOT), 'store user data outside installed skill')
        require(not args.state.is_symlink(), 'state symlink refused')
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # POSIX lock avoids lost updates from overlapping chats. No unsupported Windows claim.
        # Do not follow a substituted lock path or chmod an unrelated target.
        # O_NONBLOCK also prevents a FIFO from hanging before its type is checked.
        fd = os.open(str(path) + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(fd, 'a') as lock:
            info = os.fstat(lock.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                    'ledger lock must be a regular file with no additional hard links')
            os.fchmod(lock.fileno(), 0o600)
            acquire_ledger_lock(lock)
            state = validate_state(read_json_file(path)) if path.exists() else None
            if args.command == 'show':
                require(state is not None, 'ledger missing')
                output = state
            else:
                require(args.input is not None, '--input required')
                data = read_json_file(args.input)
                state, output = reduce(state, args.command, data, stamp())
                atomic_write(path, state)
        print(json.dumps(output, ensure_ascii=False, indent=2))
    except (WorkflowError, KeyError, TypeError, AttributeError, IndexError, OSError, ValueError) as exc:
        print(json.dumps({'error': str(exc), 'external_actions': 0}))
        raise SystemExit(2)


if __name__ == '__main__':
    main()
