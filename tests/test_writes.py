"""Tests for the management write surface and pet endpoints."""

from __future__ import annotations

import json
import unittest
from typing import Any
from unittest.mock import AsyncMock

from pypopur.mobile import PopurAccount
from pypopur.reads import Pet, PetRecordPage
from pypopur.writes import (
    TimerInstruction,
    build_instruct,
    pet_json,
    pet_query_json,
)


class _StubApi:
    def __init__(self, result: Any) -> None:
        self.result = result
        self.request = AsyncMock(return_value=result)
        self.session = object()
        self.profile = None
        self.install_id = "install-id"

    @property
    def last_call(self) -> dict[str, Any]:
        args, kwargs = self.request.call_args
        return {"args": args, "kwargs": kwargs}


def _account(result: Any) -> tuple[PopurAccount, _StubApi]:
    api = _StubApi(result)
    return PopurAccount(api), api  # type: ignore[arg-type]


PET_ROW = {
    "id": 170099,
    "name": "Leo",
    "petType": "cat",
    "breedCode": "c000085",
    "breedName": "Hybrid",
    "sex": 1,
    "weight": 8600,
    "birth": 1660935600000,
    "avatar": "",
    "extInfo": "Leopold Zoom Roff",
    "ownerId": "284696674",
    "activeness": 1,
    "gmtCreate": 1789484055299,
    "gmtModified": 1789484718052,
}


class BuilderTests(unittest.TestCase):
    def test_pet_query_json_list(self) -> None:
        q = json.loads(pet_query_json(284696674))
        self.assertEqual(q, {"ownerId": "284696674", "bizTypes": [1]})

    def test_pet_query_json_records(self) -> None:
        q = json.loads(
            pet_query_json(
                "284696674",
                pet_id=170099,
                log_type=2,
                start_time=1000,
                end_time=2000,
                page_no=2,
                page_size=50,
            )
        )
        self.assertEqual(q["ownerId"], "284696674")
        self.assertEqual(q["bizTypes"], [1])
        self.assertEqual(q["petId"], 170099)
        self.assertEqual(q["logType"], 2)
        self.assertEqual(q["startTime"], 1000)
        self.assertEqual(q["endTime"], 2000)
        self.assertEqual(q["pageNo"], 2)
        self.assertEqual(q["pageSize"], 50)

    def test_pet_json_add(self) -> None:
        p = json.loads(
            pet_json("284696674", "Leo", weight=8600, sex=1, breed_code="c000085")
        )
        self.assertEqual(p["bizType"], 1)
        self.assertEqual(p["ownerId"], "284696674")
        self.assertEqual(p["petType"], "cat")
        self.assertEqual(p["name"], "Leo")
        self.assertEqual(p["weight"], 8600)
        self.assertEqual(p["sex"], 1)
        self.assertEqual(p["breedCode"], "c000085")
        self.assertNotIn("id", p)

    def test_pet_json_update(self) -> None:
        p = json.loads(pet_json("284696674", pet_id=170099, activeness=0))
        self.assertEqual(p["id"], 170099)
        self.assertEqual(p["activeness"], 0)

    def test_build_instruct(self) -> None:
        s = build_instruct(
            [TimerInstruction(dp_id=1, value=True, time="07:00"),
             {"dpId": 4, "value": 3, "time": "20:30"}]
        )
        self.assertEqual(
            json.loads(s),
            [{"dpId": 1, "value": True, "time": "07:00"},
             {"dpId": 4, "value": 3, "time": "20:30"}],
        )


class BeanTests(unittest.TestCase):
    def test_pet_from_json(self) -> None:
        pet = Pet.from_json(PET_ROW)
        self.assertEqual(pet.pet_id, 170099)
        self.assertEqual(pet.name, "Leo")
        self.assertEqual(pet.pet_type, "cat")
        self.assertEqual(pet.breed_code, "c000085")
        self.assertEqual(pet.breed_name, "Hybrid")
        self.assertEqual(pet.sex, 1)
        self.assertEqual(pet.weight, 8600)
        self.assertEqual(pet.ext_info, "Leopold Zoom Roff")
        self.assertEqual(pet.owner_id, "284696674")
        self.assertEqual(pet.activeness, 1)

    def test_pet_record_page_wrapped(self) -> None:
        page = PetRecordPage.from_json(
            {
                "list": [{
                    "id": "6aa950bd",
                    "devId": "dev1",
                    "dpCode": "toilet_usage_data",
                    "logType": "excretionDurationReport",
                    "matchRspVO": {"id": 170099, "matchReason": "only_one_pet"},
                    "time": 123,
                    "value": "AhXxAIQ=",
                }],
                "total": 42,
                "hasNext": True,
            }
        )
        self.assertEqual(len(page.records), 1)
        rec = page.records[0]
        self.assertEqual(rec.record_id, "6aa950bd")
        self.assertEqual(rec.dev_id, "dev1")
        self.assertEqual(rec.dp_code, "toilet_usage_data")
        self.assertEqual(rec.log_type, "excretionDurationReport")
        self.assertEqual(rec.pet_id, 170099)
        self.assertEqual(rec.match_reason, "only_one_pet")
        self.assertEqual(rec.record_time, 123)
        self.assertEqual(rec.value, "AhXxAIQ=")
        self.assertEqual(page.total, 42)
        self.assertTrue(page.has_next)

    def test_pet_record_page_bare_list(self) -> None:
        page = PetRecordPage.from_json([{"petId": 1, "time": 5}])
        self.assertEqual(page.records[0].pet_id, 1)
        self.assertEqual(page.records[0].record_time, 5)
        self.assertIsNone(page.total)


class PetMethodTests(unittest.IsolatedAsyncioTestCase):
    async def test_pets(self) -> None:
        account, api = _account([PET_ROW])
        pets = await account.pets(284696674)
        action, version, post = api.last_call["args"]
        self.assertEqual(action, "m.ha.pet.group.list")
        self.assertEqual(version, "1.0")
        self.assertEqual(
            json.loads(post["queryJson"]),
            {"ownerId": "284696674", "bizTypes": [1]},
        )
        self.assertEqual(pets[0].name, "Leo")

    async def test_pets_empty(self) -> None:
        account, _ = _account(None)
        self.assertEqual(await account.pets(1), ())

    async def test_pet_records(self) -> None:
        account, api = _account({"list": [{"petId": 170099}], "total": 1})
        page = await account.pet_records(
            284696674, pet_id=170099, page_no=1, page_size=10,
            start_time=1000, end_time=2000, log_type=3,
        )
        action, version, post = api.last_call["args"]
        self.assertEqual(action, "m.ha.pet.record.list")
        self.assertEqual(version, "1.0")
        q = json.loads(post["queryJson"])
        self.assertEqual(q["petId"], 170099)
        self.assertEqual(q["pageNo"], 1)
        self.assertEqual(q["pageSize"], 10)
        self.assertEqual(q["startTime"], 1000)
        self.assertEqual(q["endTime"], 2000)
        self.assertEqual(q["logType"], 3)
        self.assertEqual(page.records[0].pet_id, 170099)

    async def test_add_pet(self) -> None:
        account, api = _account(True)
        await account.add_pet(
            284696674, "New Cat", sex=0, weight=4000, breed_code="c000001",
        )
        action, version, post = api.last_call["args"]
        self.assertEqual(action, "m.ha.pet.group.add")
        self.assertEqual(version, "1.0")
        p = json.loads(post["petJson"])
        self.assertEqual(p["bizType"], 1)
        self.assertEqual(p["ownerId"], "284696674")
        self.assertEqual(p["petType"], "cat")
        self.assertEqual(p["name"], "New Cat")
        self.assertEqual(p["weight"], 4000)

    async def test_update_pet(self) -> None:
        account, api = _account(True)
        await account.update_pet(284696674, 170099, weight=8700)
        action, _, post = api.last_call["args"]
        self.assertEqual(action, "m.ha.pet.group.update")
        p = json.loads(post["petJson"])
        self.assertEqual(p["id"], 170099)
        self.assertEqual(p["weight"], 8700)

    async def test_delete_pet_uses_update(self) -> None:
        account, api = _account(True)
        await account.delete_pet(284696674, 170099)
        action, _, post = api.last_call["args"]
        self.assertEqual(action, "m.ha.pet.group.update")
        p = json.loads(post["petJson"])
        self.assertEqual(p["id"], 170099)
        self.assertEqual(p["activeness"], 0)


class DeviceManagementTests(unittest.IsolatedAsyncioTestCase):
    async def test_rename_device(self) -> None:
        account, api = _account(True)
        await account.rename_device("dev1", "New Name")
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("thing.m.device.name.update", "1.0"))
        self.assertEqual(post, {"devId": "dev1", "name": "New Name"})

    async def test_update_device(self) -> None:
        account, api = _account(True)
        await account.update_device("dev1", name="N", icon="i.png")
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("thing.m.device.update", "1.3.1"))
        self.assertEqual(post, {"devId": "dev1", "icon": "i.png", "name": "N"})

    async def test_remove_device(self) -> None:
        account, api = _account(True)
        await account.remove_device("dev1")
        action, version, post = api.last_call["args"]
        self.assertEqual(
            (action, version), ("thing.m.app.smart.local.device.remove", "1.0")
        )
        self.assertEqual(post, {"deviceId": "dev1"})

    async def test_confirm_firmware_upgrade(self) -> None:
        account, api = _account(True)
        await account.confirm_firmware_upgrade("dev1", 0)
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("thing.m.device.upgrade.confirm", "3.0"))
        self.assertEqual(post, {"devId": "dev1", "type": 0})

    async def test_cancel_firmware_upgrade(self) -> None:
        account, api = _account(True)
        await account.cancel_firmware_upgrade("dev1", 9)
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("thing.m.device.upgrade.cancel", "1.0"))
        self.assertEqual(post, {"devId": "dev1", "type": 9})

    async def test_auto_upgrade(self) -> None:
        account, api = _account({"value": 1})
        await account.auto_upgrade_switch("dev1")
        self.assertEqual(
            api.last_call["args"],
            ("thing.m.device.upgrade.auto.switch.get", "1.0", {"devId": "dev1"}),
        )
        await account.set_auto_upgrade("dev1", 1)
        self.assertEqual(
            api.last_call["args"],
            ("thing.m.device.upgrade.auto.switch.save", "1.0",
             {"devId": "dev1", "value": 1}),
        )


class AuthMethodTests(unittest.IsolatedAsyncioTestCase):
    async def test_send_email_code(self) -> None:
        account, api = _account(True)
        await account.send_email_code("a@b.c", country_code="1")
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("thing.m.user.email.code.send", "1.0"))
        self.assertEqual(post, {"countryCode": "1", "email": "a@b.c"})
        self.assertFalse(api.last_call["kwargs"]["session_required"])

    async def test_verify_email_code(self) -> None:
        account, api = _account(True)
        await account.verify_email_code("a@b.c", "123456", code_type=2, server="AY")
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("thing.m.user.username.code.verify", "1.0"))
        self.assertEqual(post["username"], "a@b.c")
        self.assertEqual(post["code"], "123456")
        self.assertEqual(post["codeType"], 2)
        self.assertEqual(post["server"], "AY")

    async def test_login_with_email_code(self) -> None:
        api = _StubApi({"sid": "s1", "ecode": "e1", "uid": "u1",
                        "partnerIdentity": "p1", "domain": {}})
        account = PopurAccount(api)  # type: ignore[arg-type]
        session = await account.login_with_email_code("a@b.c", "123456")
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("thing.m.user.email.code.login", "3.0"))
        self.assertEqual(post["code"], "123456")
        self.assertFalse(api.last_call["kwargs"]["session_required"])
        self.assertTrue(api.last_call["kwargs"]["encrypted"])
        self.assertEqual(session.uid, "u1")
        self.assertIs(api.session, session)

    async def test_register_email(self) -> None:
        api = _StubApi(True)
        account = PopurAccount(api)  # type: ignore[arg-type]
        token = {"token": "tok1", "publicKey": "0", "exponent": "0"}

        async def fake_token(email: str, cc: str) -> dict:
            return token

        account._login_token = fake_token  # type: ignore[method-assign]
        with unittest.mock.patch(
            "pypopur.mobile._rsa_encrypt_password", return_value="enc-pw"
        ):
            await account.register_email("a@b.c", "pw")
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("thing.m.user.email.register", "1.0"))
        self.assertEqual(post["email"], "a@b.c")
        self.assertEqual(post["token"], "tok1")
        self.assertEqual(post["ifencrypt"], 1)
        self.assertEqual(post["options"], '{"group": 1}')
        self.assertTrue(api.last_call["kwargs"]["encrypted"])

    async def test_reset_email_password(self) -> None:
        account, api = _account(True)
        await account.reset_email_password("a@b.c", "999", "newpw")
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("thing.m.user.email.password.reset", "1.0"))
        self.assertEqual(post["emailCode"], "999")
        self.assertEqual(len(post["newPasswd"]), 32)

    async def test_logout_clears_session(self) -> None:
        account, api = _account(True)
        api.session = type("S", (), {"uid": "u1"})()
        await account.logout()
        self.assertEqual(api.last_call["args"][0], "thing.m.user.loginout")
        self.assertEqual(api.last_call["args"][2], {"uniqueKey": "u1"})
        self.assertIsNone(api.session)

    async def test_cancel_account(self) -> None:
        account, api = _account(True)
        api.session = type("S", (), {"uid": "u1"})()
        await account.cancel_account()
        self.assertEqual(api.last_call["args"][0], "thing.m.user.apply.logout")
        self.assertIsNone(api.session)

    async def test_update_user(self) -> None:
        account, api = _account(True)
        await account.update_user(nickname="Nick", avatar="a.png")
        self.assertEqual(
            api.last_call["args"],
            ("thing.m.user.update", "3.3", {"nickname": "Nick", "avatar": "a.png"}),
        )

    async def test_set_temp_unit(self) -> None:
        account, api = _account(True)
        await account.set_temp_unit(1)
        self.assertEqual(
            api.last_call["args"],
            ("thing.m.user.unit.temp.update", "2.0", {"tempUnit": 1}),
        )

    async def test_update_user_timezone(self) -> None:
        account, api = _account(True)
        await account.update_user_timezone("America/Los_Angeles")
        self.assertEqual(
            api.last_call["args"],
            ("thing.m.user.timezone.update", "1.0",
             {"timezoneId": "America/Los_Angeles"}),
        )


class HomeManagementTests(unittest.IsolatedAsyncioTestCase):
    async def test_create_home(self) -> None:
        account, api = _account({"gid": 1})
        await account.create_home("Home", lon=-122.4, lat=37.7,
                                  geo_name="SF", rooms=["r1", "r2"])
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("m.life.group.location.add", "6.0"))
        self.assertEqual(post["name"], "Home")
        self.assertEqual(post["lon"], -122.4)
        self.assertEqual(post["lat"], 37.7)
        self.assertEqual(post["geoName"], "SF")
        self.assertEqual(post["rooms"], ["r1", "r2"])

    async def test_update_home(self) -> None:
        account, api = _account(True)
        await account.update_home(7, name="Renamed")
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("thing.m.location.update", "2.0"))
        self.assertEqual(post, {"gid": 7, "name": "Renamed"})

    async def test_dismiss_home(self) -> None:
        account, api = _account(True)
        await account.dismiss_home(7)
        self.assertEqual(
            api.last_call["args"],
            ("thing.m.location.dismiss", "2.0", {"gid": 7}),
        )

    async def test_sort_homes(self) -> None:
        account, api = _account(True)
        await account.sort_homes([3, 1, 7])
        self.assertEqual(
            api.last_call["args"],
            ("thing.m.location.sort", "1.0", {"ids": "3,1,7"}),
        )

    async def test_add_home_member(self) -> None:
        account, api = _account(True)
        await account.add_home_member("ABC123")
        self.assertEqual(
            api.last_call["args"],
            ("thing.m.group.invitation.member.add", "1.0",
             {"invitationCode": "ABC123"}),
        )


class StatsAndBreedTests(unittest.IsolatedAsyncioTestCase):
    async def test_device_day_stats(self) -> None:
        account, api = _account([])
        await account.device_day_stats(
            "dev1", dp_id=114, stat_type="sum",
            start_day="20260901", end_day="20260918",
        )
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("tuya.m.dp.rang.stat.day.list", "2.0"))
        self.assertEqual(post["devId"], "dev1")
        self.assertEqual(post["dpId"], 114)
        self.assertEqual(post["type"], "sum")
        self.assertEqual(post["startDay"], "20260901")
        self.assertEqual(post["endDay"], "20260918")
        self.assertNotIn("auto", post)

    async def test_pet_breeds(self) -> None:
        account, api = _account([{"breedCode": "c1", "breedName": "Hybrid"}])
        await account.pet_breeds()
        self.assertEqual(
            api.last_call["args"],
            ("tuya.m.petuser.breed.list", "1.0", {"petType": "cat"}),
        )

    async def test_storage_upload_sign(self) -> None:
        account, api = _account({"url": "https://x"})
        await account.storage_upload_sign("a.png")
        self.assertEqual(
            api.last_call["args"],
            ("tuya.m.storage.upload.sign", "3.0",
             {"uploadFileName": "a.png", "type": "image",
              "method": "PUT", "biz": "pet"}),
        )


class TimerTests(unittest.IsolatedAsyncioTestCase):
    async def test_timers_uses_verified_v1(self) -> None:
        account, api = _account([])
        await account.timers("dev1")
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("thing.m.timer.all.list", "1.0"))
        self.assertEqual(post, {"devId": "dev1"})

    async def test_timer_categories(self) -> None:
        account, api = _account([])
        await account.timer_categories("dev1")
        self.assertEqual(
            api.last_call["args"],
            ("thing.m.timer.category.list", "1.0", {"devId": "dev1"}),
        )

    async def test_timer_groups(self) -> None:
        account, api = _account([])
        await account.timer_groups("dev1", category="clean")
        self.assertEqual(
            api.last_call["args"],
            ("thing.m.timer.group.list", "2.0",
             {"bizId": "dev1", "category": "clean", "type": "timer"}),
        )

    async def test_add_timer_group(self) -> None:
        account, api = _account({"groupId": "g1"})
        await account.add_timer_group(
            category="clean", loops="0111110", time_zone="+08:00",
            instruct=[TimerInstruction(dp_id=4, value=2, time="08:00")],
        )
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("thing.m.timer.group.add", "3.0"))
        self.assertEqual(post["category"], "clean")
        self.assertEqual(post["loops"], "0111110")
        self.assertEqual(post["timeZone"], "+08:00")
        self.assertEqual(post["type"], "timer")
        self.assertEqual(
            json.loads(post["instruct"]),
            [{"dpId": 4, "value": 2, "time": "08:00"}],
        )

    async def test_add_timer_group_raw_instruct(self) -> None:
        account, api = _account(True)
        await account.add_timer_group(
            category="c", loops="0000000", time_zone="-08:00",
            instruct='[{"dpId":1,"value":true,"time":"06:00"}]',
        )
        self.assertEqual(
            api.last_call["args"][2]["instruct"],
            '[{"dpId":1,"value":true,"time":"06:00"}]',
        )

    async def test_update_timer_group(self) -> None:
        account, api = _account(True)
        await account.update_timer_group(
            "g1", category="clean", loops="1111111", time_zone="+00:00",
            instruct=[{"dpId": 1, "value": False, "time": "12:00"}],
        )
        action, version, post = api.last_call["args"]
        self.assertEqual((action, version), ("thing.m.timer.group.update", "3.0"))
        self.assertEqual(post["groupId"], "g1")
        self.assertEqual(
            json.loads(post["instruct"]),
            [{"dpId": 1, "value": False, "time": "12:00"}],
        )

    async def test_remove_timer_group(self) -> None:
        account, api = _account(True)
        await account.remove_timer_group("g1", category="clean")
        self.assertEqual(
            api.last_call["args"],
            ("thing.m.timer.group.remove", "2.0",
             {"category": "clean", "groupId": "g1", "type": "timer"}),
        )

    async def test_set_timer_group_status(self) -> None:
        account, api = _account(True)
        await account.set_timer_group_status("g1", category="clean", status=0)
        self.assertEqual(
            api.last_call["args"],
            ("thing.m.timer.group.status.update", "2.0",
             {"groupId": "g1", "category": "clean", "status": 0, "type": "timer"}),
        )

    async def test_set_timer_category_status(self) -> None:
        account, api = _account(True)
        await account.set_timer_category_status("dev1", category="clean", status=1)
        self.assertEqual(
            api.last_call["args"],
            ("thing.m.timer.category.status.update", "1.0",
             {"devId": "dev1", "category": "clean", "status": 1, "type": "timer"}),
        )


if __name__ == "__main__":
    unittest.main()
