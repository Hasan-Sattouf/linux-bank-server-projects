#!/bin/sh
#set -eu

#cheak if bank_server.log file is exist
if [  ! -f bank_server.log ]
  then 
    echo "\"bank_server.log\" file does not exist!"
    exit 1
fi

#function of Failed Login Report servic
failed_login_report() {
  echo "\n\t===== Failed Login Report ====="
  
   # it can be printed dirictly without variables
  failed_records=$( grep "\[ERROR\]" bank_server.log | grep "\[AUTH\]" | grep -i "Failed login attempt")
   echo "Total number of failed login attempts: \n$( echo "$failed_records" | wc -l )"  
    
  by_CLIENT_IP=$(echo "$failed_records" | cut -d' ' -f6 | tr -d '[]' | sort | uniq -c)  
   echo "Grouped by CLIENT_IP: \n$by_CLIENT_IP"
  
  by_USER=$(echo "$failed_records" | cut -d' ' -f5 | tr -d '[]' | sort | uniq -c)
   echo "Grouped by USER: \n$by_USER"
  
  brut_force=$(echo "$by_CLIENT_IP" |
     while read count_attempts IP
     do
         if [ "$count_attempts" -ge 3 ]
         then
              echo "IP: $IP  => $count_attempts failed attempts"
         fi
     done)

   echo "Possible brute force source: \n$brut_force"
} 

#function of Query Activity Summary
query_activity_summary() {
  echo "\n\t===== Query Activity Summary ====="
  
  query_total=$(grep "\[QUERY\]" bank_server.log | wc -l)
  select_query=$(grep "\[QUERY\]" bank_server.log | grep -i "SELECT" | wc -l)
  update_query=$(grep "\[QUERY\]" bank_server.log | grep -i "UPDATE" | wc -l)
  insert_query=$(grep "\[QUERY\]" bank_server.log | grep -i "INSERT" | wc -l)
  delete_query=$(grep "\[QUERY\]" bank_server.log | grep -i "DELETE" | wc -l)
  
  echo "Number of: "
  echo "Total QUERY events: $query_total"
  echo "SELECT QUERY: $select_query"
  echo "UPDATE QUERY: $update_query"
  echo "INSERT QUERY: $insert_query"
  echo "DELETE QUERY: $delete_query"

}

#function of Slow Query Detector
slow_query_detector() {
  echo "\n\t===== Slow Query Detector ====="

  slow_query_records=$(grep "\[WARNING\]" bank_server.log | grep -i "slow query")

  echo "$slow_query_records" |
     while read line
     do
        user=$(echo "$line" | cut -d' ' -f5 | tr -d '[]')
        execution_time=$(echo "$line" | cut -d' ' -f12 | sed 's/[^0-9]//g')

        echo "User: $user\t   Execution Time: $execution_time"
     done

  # i can use : paste <(echo "$user") <(echo "$execution_times") but i need /bash not /sh

}

#function of Transaction Report
transaction_report() {
  echo "\n\t===== Transaction Report ====="

  transaction_records=$(grep "\[TRANSACTION\]" bank_server.log)
  deposit_count=$(echo "$transaction_records" | grep -i "Deposit" | wc -l)
  withdrawal_count=$(echo "$transaction_records" | grep -i "Withdrawal" | wc -l)
  declined_count=$(echo "$transaction_records" | grep -i "Declined transaction" | wc -l)
  rollback_count=$(echo "$transaction_records" | grep -i "Rollback" | wc -l)

  deposit_amount=0
  deposit_amounts=$(echo "$transaction_records" | grep -i "Deposit" | cut -d'=' -f2)
  for amount in  $deposit_amounts
  do
     deposit_amount=$((deposit_amount + amount))
  done

  withdrawal_amount=0
  withdrawal_amounts=$(echo "$transaction_records" | grep -i "Withdrawal" | cut -d'=' -f2)
  for amount in $withdrawal_amounts
  do
     withdrawal_amount=$((withdrawal_amount + amount))
  done

  echo "Deposits: $deposit_count"
  echo "Withdrawals: $withdrawal_count"
  echo "Declined transactions: $declined_count"
  echo "Rollbacks: $rollback_count"
  echo "Total deposited amount: $deposit_amount"
  echo "Total withdrawn amount: $withdrawal_amount"
}

#function of Critical Events Report
critical_events_report() {
  echo "\n\t===== Critical Events Report ====="

  critical_events=$(grep "\[CRITICAL\]" bank_server.log)

  echo "$critical_events"
}

#function of User Activity Report
user_activity_report() {
  echo "\n\t===== User Activity Report ====="

  read -p "Enter username: " name

  user_activity=$(grep -i "\[$name\]" bank_server.log)

  echo "$user_activity"
}

login_logout_session_report() {
  echo "\n\t===== Login/Logout Sessions Report ====="

  echo "SESSION_ID | LOGIN TIME | LOGOUT TIME | DURATION"

  grep "User logged in" bank_server.log | while read line
  do
    id=$(echo "$line" | sed 's/.*\[SESSION: \([^]]*\)\].*/\1/')

    login_time=$(echo "$line" | cut -d' ' -f2 | tr -d '[]')

    logout_line=$(grep "\[SESSION: $id\]" bank_server.log | grep "User logged out")

    if [ -n "$logout_line" ]
    then
      logout_time=$(echo "$logout_line" | cut -d' ' -f2 | tr -d '[]')

      login_seconds=$(echo "$login_time" | awk -F: '{print $1*3600+$2*60+$3}')
      logout_seconds=$(echo "$logout_time" | awk -F: '{print $1*3600+$2*60+$3}')

      duration=$((logout_seconds - login_seconds))

      hours=$((duration / 3600))
      minutes=$(((duration % 3600) / 60))
      seconds=$((duration % 60))

      printf "%-10s | %-10s | %-11s | %02d:%02d:%02d\n" \
      "$id" "$login_time" "$logout_time" "$hours" "$minutes" "$seconds"

    else
      printf "%-10s | %-10s | %-11s | %s\n" \
      "$id" "$login_time" "N/A" "N/A"
    fi
  done
}

#function of Events Per Hour
events_per_hour() {
  echo "\n\t===== Events Per Hour Report ====="

  hour=0

  while [ "$hour" -le 23 ]
  do
    formatted_hour=$(printf "%02d" "$hour")

    count=$(grep -c " $formatted_hour:" bank_server.log)

    printf "%s:00 - %s:59 : %d events\n" "$formatted_hour" "$formatted_hour" "$count"

    hour=$((hour + 1))
  done
}

#function of General Log Summary
general_log_summary() {
  echo "\n\t===== General Log Summary ====="

  total_events=$(wc -l < bank_server.log)

  info_count=$(grep "\[INFO\]" bank_server.log | wc -l)
  warning_count=$(grep "\[WARNING\]" bank_server.log | wc -l)
  error_count=$(grep "\[ERROR\]" bank_server.log | wc -l)
  critical_count=$(grep "\[CRITICAL\]" bank_server.log | wc -l)

  busiest=""
  busiest_count=0

  for module in AUTH QUERY TRANSACTION BACKUP
  do
    count=$(grep "\[$module\]" bank_server.log | wc -l)

    if [ "$count" -gt "$busiest_count" ]
    then
      busiest_count=$count
      busiest=$module
    fi
  done

  echo "Total events: $total_events"
  echo "Total events per log level:"
  echo "INFO: $info_count"
  echo "WARNING: $warning_count"
  echo "ERROR: $error_count"
  echo "CRITICAL: $critical_count"
  echo "Busiest Module: $busiest"
  echo "Module Events: $busiest_count"
}

#function of menu
menu() {
 echo "\n\t===== Bank Database Server Log Analyzer ====="

 while :
 do
   echo
   echo "1- Failed Login Report"
   echo "2- Query Activity Summary"
   echo "3- Slow Query Detector"
   echo "4- Transaction Report"
   echo "5- Critical Events Report"
   echo "6- User Activity Report"
   echo "7- Login/Logout Sessions Report"
   echo "8- Events Per Hour"
   echo "9- General Log Summary"
   echo "10- Exit"

   echo
   read -p "Choose: " choice

   case "$choice" in
      1) failed_login_report;;
      2) query_activity_summary;;
      3) slow_query_detector;;
      4) transaction_report;;
      5) critical_events_report;;
      6) user_activity_report;;
      7) login_logout_session_report;;
      8) events_per_hour;;
      9) general_log_summary;;
      10) echo "Good Bye :)"
          exit 0;;
      *) echo "Invalid choice! Please enter a number from 1 to 10.";;
   esac
 done

}

menu
