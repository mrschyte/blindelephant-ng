from blindelephant_ng import Database, guess

# tech-stack detection
# dbs = {
#    _id: Database.load('{}.pkl'.format(_id))
#    for _id in ('presta', 'joomla', 'textpattern', 'drupal', 'wordpress', 'magento')
# }
# print(go_figure(dbs, 'https://www.example.com'))

# single fingerprinting
# db = Database.load('presta.pkl')
# print(guess(db, 'https://www.example.com', url_filter=skip_suspicious))
    
# database generation
# db = Database()
# db.generate('wordpress.dist')
# db.save('wordpress.pkl')
