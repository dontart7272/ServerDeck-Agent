# Recreate reviewable document/evidence checksums after all logs and docs settle.
from pathlib import Path
import hashlib
base = Path(__file__).resolve().parent
root = base.parents[2]
docs_root = root / 'Документация ServerDeck'
documents = {root/'AGENTS.md', *list((root/'agent').glob('*.md')), *list(docs_root.glob('*.md')), *list((docs_root/'Документация ServerDeck Agent').glob('*.md'))}
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
(base/'documents.sha256').write_text(''.join(digest(p)+'  '+p.relative_to(root).as_posix()+'\n' for p in sorted(documents)), encoding='utf-8', newline='\n')
(base/'evidence.sha256').write_text(''.join(digest(p)+'  '+p.relative_to(base).as_posix()+'\n' for p in sorted(base.rglob('*')) if p.is_file() and p.name!='evidence.sha256'),encoding='utf-8',newline='\n')
print('Sealed',len(documents),'documents and current evidence; run verify.ps1')
