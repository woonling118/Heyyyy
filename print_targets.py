from SEUGymRsvHelper import SEUGymRsvHelper

def list_all_targets():
    helper = SEUGymRsvHelper()

    print("正在拉取所有可预约资源...")
    payload = {
        "operationName": "findResourcesAllByAccount",
        "query": '''
        query findResourcesAllByAccount($first: Int, $offset: Int) {
            findResourcesAllByAccount(first: $first, offset: $offset) {
                id
                resources_name
                resourcesDate {
                    start
                }
                resourcesTimeSlot {
                    id
                    kssj
                    jssj
                }
            }
        }
        ''',
        "variables": {
            "first": 50,
            "offset": 0
        }
    }

    response = helper.sess.post(helper._url_gym_sysquery, json=payload)
    data = response.json()

    resources = data["data"]["findResourcesAllByAccount"]
    for r in resources:
        print(f"\n资源: {r['resources_name']} (resource_id: {r['id']})")

        dates = [d["start"] for d in r.get("resourcesDate", [])]
        print(f"  可预约日期: {', '.join(dates) if dates else '无'}")

        for slot in r.get("resourcesTimeSlot", []):
            print(f"  - 时间段 {slot['kssj']} ~ {slot['jssj']} (timeslot_id: {slot['id']})")

if __name__ == "__main__":
    list_all_targets()