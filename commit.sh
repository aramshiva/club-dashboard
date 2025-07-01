echo "Starting the unconventional commit script!"
rm -rf .git club-dashboard_temp

git clone https://github.com/EthanJCanterbury/club-dashboard club-dashboard_temp

mv club-dashboard_temp/.git .

mv club-dashboard_temp/* . 2>/dev/null
rm -rf club-dashboard_temp



echo "Repository content and .git moved to current directory."

git add .
git commit -am "Fixes"

git push

echo "Script finished! The .git folder should be in the current directory, and commit/push attempted."
echo ""
echo "#####################################################################################"
echo "##                            FINAL WARNING                                      ##"
echo "#####################################################################################"
echo "## This workflow is highly unusual and not recommended for standard Git usage.   ##"
echo "## It can lead to repository instability, data loss, or unexpected behavior.     ##"
echo "## For most scenarios, cloning directly into the desired directory (e.g., 'git  ##"
echo "## clone <URL> .') or initializing a new repo and pulling is the correct approach. ##"
echo "#####################################################################################"