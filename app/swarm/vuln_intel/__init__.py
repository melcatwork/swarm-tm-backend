from .intel_syncer import IntelSyncer
from .intel_db import IntelDatabase
import asyncio
import os

def run_sync(force: bool = False):
    db = IntelDatabase()
    syncer = IntelSyncer(
        db=db,
        nvd_api_key=os.getenv('NVD_API_KEY'),
        github_token=os.getenv('GITHUB_TOKEN'),
    )
    asyncio.run(syncer.sync_all(force=force))
    state = db.get_sync_state()
    for source, info in state.items():
        print(f'{source}: {info["record_count"]} records '
              f'(last sync: {info["last_sync"]})')
