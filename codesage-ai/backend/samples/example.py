import os

def run_command(user_input):
    try:
        return eval(user_input)
    except:
        return None

if __name__ == "__main__":
    run_command(input("Expression: "))
