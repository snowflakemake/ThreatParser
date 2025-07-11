from collections import defaultdict

def extract_groups(self, console, ttps, attack_data, numbers_of_groups):

    observed_techniques = {ttp['value'] for ttp in ttps if ttp['type'] == 'TTP'}

    group_scores = defaultdict(lambda: {"match_count": 0, "matched_ttps": []})

    for ttp in ttps:
        stix_id = get_stix_id_from_tid(attack_data, ttp['value'])
        for group in attack_data.get_groups_using_technique(stix_id):
            group_name = group['object'].name

            group_scores[group_name]["match_count"] += 1
            group_scores[group_name]["matched_ttps"].append(ttp['value'])

        total_ttps = len(observed_techniques)
        ranked = sorted(group_scores.items(), key=lambda x: x[1]["match_count"], reverse=True)

    # Add probability score
    for group, data in ranked:
        data["probability"] = round(data["match_count"] / total_ttps, 2)

    return ranked[:numbers_of_groups]  # Top most likely groups

def get_stix_id_from_tid(attack_data, tid):
    for technique in attack_data.get_techniques():
        external_refs = technique.external_references
        for ref in external_refs:
            if ref["source_name"] == "mitre-attack" and ref["external_id"] == tid:
                return technique.id  # STIX ID
    return None