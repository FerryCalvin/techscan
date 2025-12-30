#!/usr/bin/env python3
"""Analyze the URL list to count entries with paths."""

urls = """360.fisip.unair.ac.id
5mtcompetition.fst.conference.unair.ac.id
aac.unair.ac.id
bpi.unair.ac.id
bpi.unair.ac.id/upg/
fh.unair.ac.id
fh.unair.ac.id/aiils/
fh.unair.ac.id/caccp/
fh.unair.ac.id/clep/
fh.unair.ac.id/EBT/
fh.unair.ac.id/hrls/
fh.unair.ac.id/hukum-bisnis/
fh.unair.ac.id/hukum-kesehatan/
fh.unair.ac.id/Jean-Monnet-Modules-EU-TSD/
fh.unair.ac.id/konstitusi-ketatapemerintahan
fh.unair.ac.id/marc/
fh.unair.ac.id/moda/
fh.unair.ac.id/pusaka/
fh.unair.ac.id/syariah/
fh.unair.ac.id/ukbh/
fh.unair.ac.id/v2/
fh.unair.ac.id/Vliruos-VUB-UNAIR/
fib.unair.ac.id
fib.unair.ac.id/basasindo/
fib.unair.ac.id/basasing/
fib.unair.ac.id/ilmuhumaniora/
fib.unair.ac.id/ilmulinguistik/
fib.unair.ac.id/ilmusejarah/
fib.unair.ac.id/mksb/
fib.unair.ac.id/studikejepangan/
fkg.unair.ac.id
fkg.unair.ac.id/bcprof/
fkg.unair.ac.id/conserv/
fkg.unair.ac.id/ibmm/
fkg.unair.ac.id/ikga/
fkg.unair.ac.id/ipm/
fkg.unair.ac.id/konserv/
fkg.unair.ac.id/magister/
fkg.unair.ac.id/new/
fkg.unair.ac.id/om/
fkg.unair.ac.id/oms/
fkg.unair.ac.id/ortho/
fkg.unair.ac.id/orto/
fkg.unair.ac.id/pediatric/
fkg.unair.ac.id/perio-en/
fkg.unair.ac.id/perio-id/
fkg.unair.ac.id/prostho/
fkg.unair.ac.id/prosto/
fkg.unair.ac.id/radiologi/
fkg.unair.ac.id/research-center/
fkg.unair.ac.id/s1prof/
fkg.unair.ac.id/s2/
fkg.unair.ac.id/s3/
fkg.unair.ac.id/simdagilut/
ftmm.unair.ac.id
ftmm.unair.ac.id/rasena/
itd.unair.ac.id
itd.unair.ac.id/intervect2018/
itd.unair.ac.id/itd/
itd.unair.ac.id/research/
itd.unair.ac.id/sgdd.workshop/
ners.unair.ac.id
ners.unair.ac.id/wp/
pasca.unair.ac.id
pasca.unair.ac.id/2024/
patientsafety.unair.ac.id/
pendidikan.unair.ac.id
pendidikan.unair.ac.id/en/
rumahsakit.unair.ac.id
rumahsakit.unair.ac.id/site/
rumahsakit.unair.ac.id/tidcenter/
rumahsakit.unair.ac.id/web/
rumahsakit.unair.ac.id/website/
sarpras.rumahsakit.unair.ac.id
sarpras.rumahsakit.unair.ac.id/helpdesk/
sarpras.rumahsakit.unair.ac.id/rsua-instalasi/
sim.ditkeu.unair.ac.id
sim.ditkeu.unair.ac.id/ailg
sim.ditkeu.unair.ac.id/app
sim.ditkeu.unair.ac.id/dpa
sim.ditkeu.unair.ac.id/fri
sim.ditkeu.unair.ac.id/infohonor
sim.ditkeu.unair.ac.id/ltmpt
sim.ditkeu.unair.ac.id/ltmpt2
sim.ditkeu.unair.ac.id/monev
sim.ditkeu.unair.ac.id/penugasan
sim.ditkeu.unair.ac.id/rekanan
sim.ditkeu.unair.ac.id/rgu
sim.ditkeu.unair.ac.id/sbm
sim.ditkeu.unair.ac.id/snpmb
sim.ditkeu.unair.ac.id/ua_surat
sim.ditkeu.unair.ac.id/vmp
simgos.plk.unair.ac.id/webservice/
ukm.unair.ac.id
ukm.unair.ac.id/e_sport/
ult.unair.ac.id
ult.unair.ac.id/ais"""

lines = [l.strip() for l in urls.strip().split('\n') if l.strip()]

# Count URLs with paths
with_path = [l for l in lines if '/' in l]
without_path = [l for l in lines if '/' not in l]

print(f"Total sample URLs: {len(lines)}")
print(f"With path: {len(with_path)}")
print(f"Without path: {len(without_path)}")
print("\nURLs with paths (sample):")
for u in with_path[:20]:
    print(f"  {u}")

# Check for potential duplicates (same domain with/without trailing slash)
normalized = {}
for u in lines:
    norm = u.rstrip('/')
    if norm in normalized:
        print(f"\nPotential duplicate: {u} vs {normalized[norm]}")
    else:
        normalized[norm] = u

print(f"\nUnique normalized URLs: {len(normalized)}")
