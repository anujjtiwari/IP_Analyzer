db.createUser(
  {
    user: "admin_ip_analyzer",
    pwd: "root_ip_analyzer",
    roles: [ { role: "readWrite", db: "ip_analyzer" } ]
  }
)

db.createCollection("queries")
db.createCollection("users")
db.createCollection("temp_users")