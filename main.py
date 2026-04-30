from dotenv import load_dotenv

# local files
from agents.orchestrator import orchestrator, is_in_scope
from agents.recon import run_recon

load_dotenv()

def menu():
    print("\n=== Penetration Testing Menu ===")
    options = {
        1: ("Full Orchestration", "orchestrator"),
        2: ("Reconnaissance Only", "recon"),
        3: ("Check If Target In Scope", "scope_check")
    }

    for num, (name, _) in options.items():
        print(f"{num}. {name}")
    print("0. Exit")

    try:
        choice = int(input("\nSelect an option: "))
        
        if choice == 0:
            print("Exiting...")
            return
        
        if choice not in options:
            print("Invalid choice. Please try again.")
            return menu()
        
        option_name, option_key = options[choice]
        target = input("Enter target: ").strip()
        
        if not target:
            print("Target cannot be empty.")
            return menu()
        
        print(f"\nExecuting {option_name} on {target}...")
        
        if option_key == "orchestrator":
            result = orchestrator(target)
        elif option_key == "recon":
            result = run_recon(target)
        elif option_key == "scope_check":
            result = {"target": target, "in_scope": is_in_scope(target)}
        
        print(f"\nResult: {result}")
        
    except ValueError:
        print("Invalid input. Please enter a number.")
        return menu()
    except Exception as e:
        print(f"Error occurred: {e}")
        import traceback
        traceback.print_exc()
        return menu()
    
    # Ask if user wants to continue
    cont = input("\nWould you like to perform another action? (y/n): ").lower()
    if cont == 'y':
        return menu()
    else:
        print("Goodbye!")

if __name__ == "__main__":
    menu()

