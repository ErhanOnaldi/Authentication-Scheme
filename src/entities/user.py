# src/entities/user.py

class User:
    def __init__(self, user_id, password):
        self.user_id = user_id
        self.password = password
    
    def store_in_smart_card(self, Vi, RTi):
        self.smart_card['Vi'] = Vi
        self.smart_card['RTi'] = RTi

# Test
if __name__ == "__main__":
    user = User("user1", "password123")
    print(f"User ID: {user.user_id}, Password: {user.password}")
