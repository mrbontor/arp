function dateConverter() {
    let a = new Date();
    let year = a.getFullYear()
    let month = ("0" + (a.getMonth() + 1)).slice(-2)
    let date = ("0" + a.getDate()).slice(-2)
    let hour = ("0" + a.getHours()).slice(-2)
    let min = ("0" + a.getMinutes()).slice(-2)
    let sec = ("0" + a.getSeconds()).slice(-2)
    let time = year + '-' + month + '-' + date + ' ' + hour + ':' + min + ':' + sec;
    return time;
}


module.exports = dateConverter