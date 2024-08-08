import json

# Load rules from the JSON file
def load_rules(filename="rules.json"):
    with open(filename, "r") as file:
        rules = json.load(file)["rules"]
    return rules

def apply_rule(features, rule):
    try:
        condition = rule["condition"]
        return eval(condition)
    except Exception as e:
        print(f"Error evaluating rule {rule['description']}: {e}")
        return False

# Load rules when the module is imported
intrusion_rules = load_rules()

