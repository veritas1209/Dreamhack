
print("=== Calculator ===")
print("Enter math expressions")
print("Type 'exit' to quit")
print("=" * 25)

while True:
    user_input = input(">>> ").strip()

    if user_input.lower() == 'exit':
        print("Goodbye!")
        break

    try:
        result = exec('"' + user_input + '"')
        if '=' not in user_input and any(op in user_input for op in ['+', '-', '*', '/']):
            print(f"= {eval(user_input)}")
    except Exception as e:
        print(f"Error: {e}")
