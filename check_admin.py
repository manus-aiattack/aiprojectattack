import asyncio
import asyncpg

async def check_admin():
    db_url = "postgresql://dlnk_user:18122542@localhost:5432/dlnk"
    
    print("Connecting to database...")
    
    try:
        conn = await asyncpg.connect(db_url)
        
        rows = await conn.fetch("SELECT username, api_key, role FROM users WHERE role = 'admin'")
        
        if rows:
            print("\n✅ Admin users found:\n")
            for row in rows:
                print(f"Username: {row['username']}")
                print(f"API Key: {row['api_key']}")
                print(f"Role: {row['role']}")
                print("-" * 50)
        else:
            print("\n⚠️  No admin users found")
        
        await conn.close()
        
    except Exception as e:
        print(f"\n❌ Error: {e}")

asyncio.run(check_admin())
