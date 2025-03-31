import sqlite3

conn = sqlite3.connect('database.db')
print('BD successfully connected.')
conn.execute('CREATE TABLE patients (name TEXT, surname TEXT, age INT, illness TEXT, parameter TEXT, parameter_val REAL )')
print('Table created successfully.')
conn.close()