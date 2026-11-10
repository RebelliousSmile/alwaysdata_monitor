-- Sourdine d'un incident (#50) : jusqu'à cette date (secondes Unix), le
-- veilleur n'envoie plus de rappel. L'e-mail d'ouverture et celui de clôture
-- ne sont pas concernés.
ALTER TABLE incidents ADD COLUMN snoozed_until INTEGER;
