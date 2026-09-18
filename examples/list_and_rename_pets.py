"""List the household's pets and rename one.

    python examples/list_and_rename_pets.py                # just list
    python examples/list_and_rename_pets.py Leo Leopold    # rename Leo -> Leopold

Credentials come from POPUR_EMAIL / POPUR_PASSWORD (and optional
POPUR_INSTALL_ID).
"""

import asyncio
import os
import sys
from datetime import datetime

from pypopur.mobile import MobileAppProfile, PopurAccount, ThingMobileApi


async def main() -> None:
    api = ThingMobileApi(
        MobileAppProfile.bundled_popur_app2(),
        install_id=os.environ.get("POPUR_INSTALL_ID", ""),
    )
    account = PopurAccount(api)
    await account.login(os.environ["POPUR_EMAIL"], os.environ["POPUR_PASSWORD"])

    # Pet APIs are scoped to the home (ownerId == gid).
    home_id = (await account.homes())[0]["gid"]

    pets = await account.pets(home_id)
    for pet in pets:
        print(
            f"{pet.name!r} (id {pet.pet_id}) — {pet.pet_type}, "
            f"breed={pet.breed_name or pet.breed_code}, sex={pet.sex}, "
            f"weight={pet.weight}g, ext={pet.ext_info!r}"
        )

    # Per-visit weight/duration stats: each toilet_usage_data record's
    # value decodes to {weight grams, duration seconds}.
    names = {p.pet_id: p.name for p in pets}
    page = await account.pet_records(home_id, page_size=20)
    for record in page.records:
        usage = record.toilet_usage()
        if usage is None:
            continue
        when = datetime.fromtimestamp(record.record_time / 1000)
        who = names.get(record.pet_id, "?")
        print(
            f"  {when:%Y-%m-%d %H:%M}  {who:5}  "
            f"{usage.weight_grams}g  {usage.duration_seconds}s"
        )

    if len(sys.argv) == 3:
        old, new = sys.argv[1], sys.argv[2]
        pet = next(p for p in pets if p.name == old)
        # Send the unchanged fields back too so the update doesn't blank them.
        await account.update_pet(
            home_id,
            pet.pet_id,
            name=new,
            avatar=pet.avatar,
            sex=pet.sex,
            birth=pet.birth,
            weight=pet.weight,
            breed_code=pet.breed_code,
            ext_info=pet.ext_info,
        )
        print(f"renamed {old} -> {new}")


if __name__ == "__main__":
    asyncio.run(main())
