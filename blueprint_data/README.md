# blueprint_data — synthetic knowledge + records for the NVIDIA AI Virtual Assistant blueprint

One folder per Application Theme:

- `docs/*.md` — knowledge articles the blueprint's `retrieve_knowledge` tool searches
  (keyword retrieval by default; a local embedding NIM when `BLUEPRINT_EMBED_URL` is set).
- `records.json` — the customer / patient / subscriber records `lookup_record` reads; a
  session's synthetic end-user id is bound to one record deterministically.

Everything here is SYNTHETIC demo content. No real people, accounts, orders, plants or
medical facts are represented, and every article is general information only.
