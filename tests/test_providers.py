import asyncio
import copy
import os
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

import ai_provider as ai
from tests.fixtures import registry


class ProviderTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        ai._registry = None
        ai._registry_key = None
        ai._discovery_task = None
        ai._mode = None

    def test_all_modes_and_downgrade(self):
        r = registry()
        for row in r['providers'].values(): row['online'] = True
        expected = {'auto':['meta','antigravity','custom'], 'all_three':['meta','antigravity','custom'],
                    'meta_plus_agy':['meta','antigravity'], 'meta_plus_custom':['meta','custom'], 'meta_only':['meta','meta']}
        for mode, members in expected.items():
            with self.subTest(mode=mode):
                self.assertEqual([m['provider'] for m in ai.select_ensemble(r,mode)['members']],members)
                down = registry()
                self.assertEqual([m['model'] for m in ai.select_ensemble(down,mode)['members']],list(ai.META_MODELS))
                self.assertEqual(ai.select_ensemble(down,mode,task='semantic_hunt')['members'][0]['model'],'muse-wonder-1.0')
        r['providers']['meta']['online'] = False
        with self.assertRaises(ai.ProviderUnavailable): ai.select_ensemble(r)

    async def test_placeholder_never_calls_http(self):
        cfg = ai.configuration()
        cfg.update(CUSTOM_API_KEY='your_key_here',CUSTOM_API_URL='https://example.com/v1',CUSTOM_MODEL_NAME='openai/gpt-6-astra')
        with patch.object(ai,'_http_data',AsyncMock()) as http:
            row = await ai._probe_provider('custom',cfg)
            self.assertEqual(row['status'],'UNCONFIGURED'); http.assert_not_called()

    async def test_auth_timeout_invalid_content_excluded(self):
        cfg=ai.configuration()
        cfg.update(CUSTOM_API_KEY='fixture-key-value',CUSTOM_API_URL='https://example.com/v1/responses',CUSTOM_MODEL_NAME='openai/gpt-6-astra')
        for exc in [ai.ProviderUnavailable('HTTP 401'), ai.ProviderUnavailable('HTTP 403'), ai.ProviderUnavailable('HTTP 404'), TimeoutError(), ValueError('Provider returned no text')]:
            with patch.object(ai,'_http_data',AsyncMock(side_effect=exc)):
                row=await ai._probe_provider('custom',cfg)
                self.assertFalse(row['online'])
                if str(exc)=='HTTP 401': self.assertEqual(row['status'],'401 INVALID KEY')

    async def test_quota_cascade(self):
        cfg=ai.configuration(); cfg.update(AGY_BIN='/fake/agy',AGY_SELECTED_MODEL='claude-opus-5-5')
        help_proc=SimpleNamespace(communicate=AsyncMock(return_value=(b'--max-turns',b'')),returncode=0)
        with patch.object(ai.os.path,'isfile',return_value=True), patch.object(ai.os,'access',return_value=True), patch.object(ai.asyncio,'create_subprocess_exec',AsyncMock(return_value=help_proc)), patch.object(ai,'_cli_data',AsyncMock(side_effect=[ai.ProviderUnavailable('QUOTA_EXHAUSTED'),{'response':'OK'}])) as cli:
            row=await ai._probe_provider('antigravity',cfg)
            self.assertTrue(row['online']); self.assertEqual(row['model'],'gemini-4-argon')
            self.assertEqual(row['status'],'QUOTA FALLBACK')
            self.assertEqual(len(cli.call_args_list),2)
            self.assertIn('--max-turns',cli.call_args_list[0].args[0])

    async def test_astra_reasoning_cache_and_tariffs_both_apis(self):
        for endpoint in ['https://example.com/v1/responses','https://openrouter.ai/api/v1/chat/completions']:
            r=registry(); r['providers']['custom'].update(online=True,models=['openai/gpt-6-astra'])
            seen=[]
            async def data(url,key,payload,timeout):
                seen.append(copy.deepcopy(payload))
                return {'output_text':'OK','usage':{'input_tokens':100,'output_tokens':20,'input_tokens_details':{'cached_tokens':40}}}
            with patch.dict(os.environ,{'CUSTOM_API_URL':endpoint,'CUSTOM_API_KEY':'fixture-key-value','CUSTOM_MODEL_NAME':'openai/gpt-6-astra','CUSTOM_REASONING_EFFORT':'medium','CUSTOM_SERVICE_TIER':''}), patch.object(ai,'discover_and_verify_providers',AsyncMock(return_value=r)), patch.object(ai,'_http_data',data):
                with ai.telemetry_scope('cache') as state:
                    await ai.query_ai('policy', 'static repository', provider='custom')
                    await ai.query_ai('patch', 'different stage instructions', provider='custom', task='patch_verification',service_tier='fast')
                    await ai.query_ai('hunt', 'static repository', provider='custom', task='semantic_hunt',service_tier='ultrafast')
                self.assertEqual([p.get('reasoning_effort',p.get('reasoning',{}).get('effort')) for p in seen],['medium','xhigh','xhigh'])
                self.assertEqual(len({p['prompt_cache_key'] for p in seen}),1)
                key='input' if endpoint.endswith('/responses') else 'messages'
                self.assertEqual(seen[0][key][0],seen[1][key][0])
                self.assertEqual(seen[2]['service_tier'],'ultrafast')
                self.assertAlmostEqual(state['calls'][0]['estimated_cost_usd'],.00164)
                self.assertEqual(state['calls'][0]['cached_input_tokens'],40)
        u={'usage_reported':True,'input_tokens':300000,'output_tokens':1000,'cached_input_tokens':100000,'cache_write_tokens':None}
        self.assertAlmostEqual(ai._cost('custom','openai/gpt-6-astra',u),4.275)
        for effort in ['none','minimal']:
            with self.assertRaises(ValueError): ai._payload('gpt-6-astra','p','s',endpoint,effort)

    async def test_offline_or_untested_provider_never_gets_task(self):
        r=registry()
        with patch.object(ai,'discover_and_verify_providers',AsyncMock(return_value=r)), patch.object(ai,'_http_data',AsyncMock()) as call:
            with self.assertRaises(ai.ProviderUnavailable): await ai.query_ai('p',provider='custom')
            with self.assertRaises(ai.ProviderUnavailable): await ai.query_ai('p',provider='meta',model='untested')
            call.assert_not_called()

    async def test_concurrent_discovery_singleflight(self):
        calls=[]
        async def probe(p,cfg):
            calls.append(p); await asyncio.sleep(.01)
            return {'provider':p,'online':True,'model':'test'}
        with patch.object(ai,'_probe_provider',probe):
            await asyncio.gather(*(ai.discover_and_verify_providers() for _ in range(8)))
            await ai.discover_and_verify_providers()
        self.assertEqual(sorted(calls),['antigravity','custom','meta'])

    async def test_all_three_auditors_execute_concurrently(self):
        r=registry()
        for row in r['providers'].values(): row['online']=True
        active, peak = 0, 0
        async def query(*args, **kwargs):
            nonlocal active, peak
            active += 1; peak=max(peak,active)
            await asyncio.sleep(.02)
            active -= 1
            return 'OK'
        with patch.object(ai,'discover_and_verify_providers',AsyncMock(return_value=r)), patch.object(ai,'query_ai',query):
            result=await ai.query_ensemble('p','s')
        self.assertEqual(len(result),3)
        self.assertEqual(peak,3)

    async def test_running_quorum_is_stable_but_configuration_changes_reprobe(self):
        calls=[]
        async def probe(provider,cfg):
            calls.append(provider)
            return {'provider':provider,'online':True,'model':'fixture'}
        with patch.object(ai,'_probe_provider',probe):
            with ai.telemetry_scope('stable'):
                await ai.discover_and_verify_providers()
                ai._registry_at=0
                await ai.discover_and_verify_providers()
                self.assertEqual(len(calls),3)
                with patch.dict(os.environ,{'CUSTOM_MODEL_NAME':'different-model'}):
                    await ai.discover_and_verify_providers()
                self.assertEqual(len(calls),6)

    async def test_credential_change_during_preflight_never_sends_live_task(self):
        async def changed(*args, **kwargs):
            os.environ['CUSTOM_API_KEY']='different-credential'
            result=registry()
            result['providers']['custom']['online']=True
            return result
        with patch.dict(os.environ,{'CUSTOM_API_KEY':'initial-credential'}), patch.object(ai,'discover_and_verify_providers',changed), patch.object(ai,'_http_data',AsyncMock()) as http:
            with self.assertRaises(ai.ProviderUnavailable):
                await ai.query_ai('live task',provider='custom')
            http.assert_not_called()

    async def test_different_configurations_do_not_share_a_preflight(self):
        async def probe(provider,cfg):
            await asyncio.sleep(.02)
            return {'provider':provider,'online':True,'model':cfg['CUSTOM_MODEL_NAME']}
        with patch.dict(os.environ,{'CUSTOM_MODEL_NAME':'first-model'}), patch.object(ai,'_probe_provider',probe):
            first=asyncio.create_task(ai.discover_and_verify_providers())
            await asyncio.sleep(0)
            os.environ['CUSTOM_MODEL_NAME']='second-model'
            second=asyncio.create_task(ai.discover_and_verify_providers())
            one,two=await asyncio.gather(first,second)
        self.assertEqual(one['providers']['custom']['model'],'first-model')
        self.assertEqual(two['providers']['custom']['model'],'second-model')

    def test_empty_and_truncated_content_not_verified(self):
        for data in [{},{'output_text':''},{'status':'incomplete','output_text':'OK'},{'choices':[{'message':{'content':'OK'},'finish_reason':'length'}]}]:
            with self.assertRaises((ValueError,KeyError)): ai._content(data)
