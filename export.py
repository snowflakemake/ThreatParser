import csv

def export_to_csv(data, filename, numbers_of_data_types=1):
    if not data:
        return
    
    if numbers_of_data_types == 1:
        data = [data]

    keys = []
    for data_type in data:
        keys.extend(data_type[0].keys())
    keys = list(set(keys))  # Remove duplicates
    priority = ['type', 'value', 'name']
    keys = sorted(keys, key=lambda x: (priority.index(x) if x in priority else len(priority), x))


    for data_type in data:
        if data_type == data[0]:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=keys)

                writer.writeheader()
                for item in data_type:
                    writer.writerow(item)
        else:
            with open(filename, 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=keys)
                for item in data_type:
                    writer.writerow(item)